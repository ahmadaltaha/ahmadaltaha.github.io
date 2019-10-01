#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>

#include "socket.h"
#include "jobprotocol.h"

#define QUEUE_LENGTH 5
#define MAX_CLIENTS 20
#define SHUT_DOWN "[SERVER] Shutting down"
#define MAX_CONCURRENT "[SERVER] Client disconnected: max concurrent connections reached"
#define JOB_EXIT_SIGNAL_NN "[Job %d] Exited due to signal.\r\n"
#define JOB_EXIT_SIGNAL_UN "[Job %d] Exited due to signal.\n"
#define JOB_EXIT_STATUS_NN "[JOB %d] Exited with status %d.\r\n"
#define JOB_EXIT_STATUS_UN "[JOB %d] Exited with status %d.\n"
#define MAX_JOBS_NN "[SERVER] MAXJOBS exceeded\r\n"
#define MAX_JOBS_UN "[SERVER] MAXJOBS exceeded\n"
#define MAX_ARGS 30

#ifndef JOBS_DIR
    #define JOBS_DIR "./jobs/"
#endif

int sigint_received;
JobList job_list;
fd_set all_fds, listen_fds;
int pids[MAX_JOBS];
int pids_index = 0;

void SIGCHLDhandler(int code) {
    int status;
    if(job_list.first != NULL) {
        JobNode *curr = job_list.first;
        pids_index = 0;
        for (int i = 0; i < job_list.count; i++) {
            if (waitpid(curr->pid, &status, WNOHANG) == 0){
                curr = curr->next; 
            }
            else {
                curr->dead = 1;
                pids[pids_index] = curr->pid;
                pids_index++;
                int watchfd = curr->watcher_list.first->client_fd;
                char buf[BUFSIZE];
                if(WIFSIGNALED(status)) {
                    printf(JOB_EXIT_SIGNAL_UN, curr->pid);
                    snprintf(buf, BUFSIZE, JOB_EXIT_SIGNAL_NN, curr->pid);
                }
                else {
                    int exit_code = WEXITSTATUS(status);
                    printf(JOB_EXIT_STATUS_UN, curr->pid, exit_code);
                    snprintf(buf, BUFSIZE, JOB_EXIT_STATUS_NN, curr->pid, exit_code);
                }
                write(watchfd, buf, strlen(buf));
                curr = curr->next;
            }
        }
    }
}

void SIGINThandler(int code) {
    sigint_received = 1;
}

/* Search the first n characters of buf for a network newline (\r\n).
 * Return one plus the index of the '\n' of the first network newline,
 * or -1 if no network newline is found.
 */
int find_network_newline(const char *buf, int inbuf) {
    for (int i=0;i < inbuf-1; i++) {
        if (buf[i] == '\r') {
            if (buf[i+1] == '\n') {
                return 1 + i + 1; 
            }
        }
    }
    return -1;
}

int find_newline(const char *buf, int inbuf) {
    for (int i=0;i < inbuf-1; i++) {
        if (buf[i] == '\n') {
            return i + 1; 
        }
    }
    return -1;
}

/* Read characters from fd and store them in buffer. Announce each message found
 * to watchers of job_node with the given format, eg. "[JOB %d] %s\n".
 */
void process_job_output(JobNode *job_node, int fd, Buffer *buffer, char *format){
        int room = sizeof(buffer->buf) - buffer->inbuf;  // How many bytes remaining in buffer?
        char *after = buffer->buf + buffer->inbuf;       // Pointer to position after the data in buf
        int nbytes;
        char temp[BUFSIZE+1];
        if ((nbytes = read(fd, after, room)) > 0) {
            buffer->inbuf += nbytes;
            int where;
            if ((where = find_network_newline(buffer->buf, buffer->inbuf)) > 0) {
                char tempchar = buffer->buf[where];
                buffer->buf[where] = '\0';
                snprintf(temp, BUFSIZE, format, job_node->pid, buffer->buf);
                buffer->buf[where] = tempchar;
                write(job_node->watcher_list.first->client_fd, temp, strlen(temp));
                temp[strlen(temp)-2] = '\n';
                temp[strlen(temp)-1] = '\0';
                printf("%s", temp);
                buffer->inbuf = buffer->inbuf - where;
                memmove(buffer->buf, buffer->buf+where, buffer->inbuf);
            }
            if ((where = find_newline(buffer->buf, buffer->inbuf)) > 0) {
                char tempchar = buffer->buf[where+1];
                buffer->buf[where-1] = '\r';//buf[where] = index of \n + 1 so we strip newline into NN
                buffer->buf[where] = '\n';
                buffer->buf[where+1] = '\0';
                snprintf(temp, BUFSIZE, format, job_node->pid, buffer->buf);
                buffer->buf[where+1] = tempchar;
                write(job_node->watcher_list.first->client_fd, temp, strlen(temp));
                buffer->inbuf = buffer->inbuf - where - 1;
                memmove(buffer->buf, buffer->buf+where+1, buffer->inbuf);
                printf("%s", temp);
            }
            
            room = sizeof(buffer->buf) - buffer->inbuf;
            after = buffer->buf + buffer->inbuf;
            if (room == 0) {
                printf("*(SERVER)* Buffer from job %d is full. Aborting job.\n", job_node->pid);
                snprintf(temp, BUFSIZE, "*(SERVER)* Buffer from job %d is full. Aborting job.\r\n", job_node->pid);
                write(job_node->watcher_list.first->client_fd, temp, strlen(temp));
                kill(job_node->pid, SIGKILL);
            }
        }
}   

/* Removes a job from the given job list and frees it from memory.
 * Returns 0 if successful, or -1 if not found.
 */
int remove_job(JobList *job_list, int pid) {
    if(job_list->count == 0) {
        return -1;
    }
    JobNode *curr = job_list->first;
    JobNode *prev = curr;
    if(job_list->count == 1) {//only one job

        if (curr->pid == pid) {
            FD_CLR(curr->stdout_fd, &all_fds);
            FD_CLR(curr->stderr_fd, &all_fds);
            free(curr->watcher_list.first);
            close(curr->stdout_fd);
            close(curr->stderr_fd);
            pids_index -= 1;
            free(curr);
            job_list->count = job_list->count - 1;
            job_list->first = NULL;
            return 0;
        }
        else {
            return -1;
        }
    }
    else {
        if (curr->pid == pid) {//first in list
            job_list->first = job_list->first->next;
            FD_CLR(curr->stdout_fd, &all_fds);
            FD_CLR(curr->stderr_fd, &all_fds);
            free(curr->watcher_list.first);
            close(curr->stdout_fd);
            close(curr->stderr_fd);
            pids_index -= 1;
            free(curr);
            job_list->count = job_list->count - 1;
            return 0;
        }
        for (int i = 0; i < job_list->count-1; i++) {//somewhere in the middle
            if(curr->pid == pid) {
                prev->next = curr->next;
                FD_CLR(curr->stdout_fd, &all_fds);
                FD_CLR(curr->stderr_fd, &all_fds);
                free(curr->watcher_list.first);
                close(curr->stdout_fd);
                close(curr->stderr_fd);
                pids_index -= 1;
                
                free(curr);
                job_list->count = job_list->count - 1;
                return 0;
            }
            prev = curr;
            curr = curr->next;
        }
        if(curr->pid == pid) {//last job
            prev->next = curr->next;
            FD_CLR(curr->stdout_fd, &all_fds);
            FD_CLR(curr->stderr_fd, &all_fds);
            free(curr->watcher_list.first);
            close(curr->stdout_fd);
            close(curr->stderr_fd);
            pids_index -= 1;
            free(curr);
            job_list->count = job_list->count - 1;
            return 0;    
        }
    }
    return -1;
}

/* Accept a connection and adds them to list of clients.
 * Return the new client's file descriptor or -1 on error.
 */
int setup_new_client(int listen_fd, Client *clients) {
    int user_index = 0;
    while (user_index < MAX_CLIENTS && clients[user_index].socket_fd != -1) {
        user_index++;
    }
    int client_fd = accept_connection(listen_fd);
    if (client_fd < 0) {
        return -1;
    }
    if (user_index >= MAX_CLIENTS) {
        fprintf(stderr, MAX_CONCURRENT);
        close(client_fd);
        return -1;
    }
    clients[user_index].socket_fd = client_fd;
    return client_fd;
}

/* Read as much as possible from file descriptor fd into the given buffer.
 * Returns number of bytes read, or 0 if fd closed, or -1 on error.
 */
int read_to_buf(int fd, Buffer *buffer) {
    int room = sizeof(buffer->buf) - buffer->inbuf;  // How many bytes remaining in buffer?
    char *after = buffer->buf + buffer->inbuf;       // Pointer to position after the data in buf
    int nbytes;
    while ((nbytes = read(fd, after, room)) > 0) {
        buffer->inbuf += nbytes;
        int where;
        if ((where = find_network_newline(buffer->buf, buffer->inbuf)) > 0) {
            buffer->buf[where] = '\0';
            buffer->inbuf = buffer->inbuf - where;
            return nbytes;
        }
        room = sizeof(buffer->buf) - buffer->inbuf;
        after = buffer->buf + buffer->inbuf;
    }
    if (nbytes == 0) {
            return 0;
    }
    return -1;   
}

void write_jobs(Client *client, JobList *job_list) {
    if (job_list->count != 0) {
        JobNode *currNode = job_list->first;
        char msg[BUFSIZE] = "[SERVER] ";
        char job_pid[15];
        for (int i = 0; i < job_list->count; i++) {
            job_pid[0] = '\0';
            snprintf(job_pid, 15, "%d ", currNode->pid);
            strncat(msg, job_pid, 15);
            currNode = currNode->next;
        }
        printf("%s\n", msg);
        strncat(msg, "\r\n", 3);
        write(client->socket_fd, msg, strlen(msg));
    }
    else {
        write(client->socket_fd, "[SERVER] No currently running jobs\r\n", strlen("[SERVER] No currently running jobs\r\n"));
        printf("[SERVER] No currently running jobs\n");
    }
}

/* Sends SIGKILL to the given job_pid only if it is part of the given
 * job list. Returns 0 if successful, 1 if it is not found, or -1 if
 * the kill command failed.
 */
int kill_job(Client *client, JobList *job_list, char *msg) {
    msg = msg + 5;
    char msg_cpy[15];
    strncpy(msg_cpy, msg, 14);
    char write_msg_nn[BUFSIZE];
    char write_msg_un[BUFSIZE];
    snprintf(write_msg_nn, BUFSIZE, "[SERVER] Job %s not found\r\n", msg);
    snprintf(write_msg_un, BUFSIZE, "[SERVER] Job %s not found\r\n", msg);
    char pid[15];
    int length = 0;
    while(*msg) {
        if(isdigit(*msg) == 0) {
            printf("%s", write_msg_un);
            write(client->socket_fd, write_msg_nn, strlen(write_msg_nn));
            return -1;
        }
        else {
            pid[length] = *msg;
            length = length + 1;
            msg = msg + 1;
        }
    }
    pid[length+1] = '\0';
    length = length + 1;
    int pid_int = strtol(pid, NULL, 10);
    JobNode *curr = job_list->first;
    for(int i = 0; i < job_list->count; i++) {
        if(curr->pid == pid_int) {
            if (kill(pid_int, SIGKILL) == -1) {
                return -1;
            }
            curr->dead = 1;
            return 0;
        }
        curr = curr->next;
    }
    printf("%s", write_msg_un);
    write(client->socket_fd, write_msg_nn, strlen(write_msg_nn));
    return 1;
}

int run(char *msg, Client *client, JobList *job_list, fd_set *all_fds) {
    msg = msg+4;
    char *jobname = strtok(msg, " ");
    if(jobname == NULL) {
        return -1;
    }
    if(strstr(jobname, "/") != NULL) {
        perror("[SERVER]\'/\' found. Invalid command.\n");
        write(client->socket_fd, "[SERVER]\'/\' found. Invalid command.\n", strlen("[SERVER]\'/\' found. Invalid command.\n"));
        return -1;
    }
    char *token;
    char *args[MAX_ARGS];
    int argc = 1;
    args[0] = jobname;
    while((token = strtok(NULL, " ")) != NULL) {
        args[argc] = token;
        argc = argc+1;
    }
    args[argc] = NULL;
    int stdout_fd[2];
    int stderr_fd[2];
    if (pipe(stdout_fd) < 0) {
        perror("pipe");
    }
    if (pipe(stderr_fd) < 0) {
        perror("pipe");
    }
    int res;
    if ((res = fork()) < 0) {
        perror("fork");
    }
    if (res > 0) {//PARENT
        close(stdout_fd[1]);
        close(stderr_fd[1]);//close writing
        FD_SET(stdout_fd[0], all_fds);
        FD_SET(stderr_fd[0], all_fds);//set fds

        JobNode *job_node = malloc(sizeof(JobNode));//create job
        job_node->stdout_fd = stdout_fd[0];
        job_node->stderr_fd = stderr_fd[0];
        job_node->pid = res;
        job_node->dead = 0;
        job_node->next = NULL;

        job_node->watcher_list.first = malloc(sizeof(struct watcher_node));//set watchers
        job_node->watcher_list.first->client_fd = client->socket_fd;
        job_node->watcher_list.first->next = NULL;

        job_node->stdout_buffer.inbuf = 0;//set buffer
        job_node->stderr_buffer.inbuf = 0;
        
        
        if (job_list->count == 0) {
            job_list->first = job_node;
        }
        else {
            JobNode *curr = job_list->first;
            for(int i = 0; i < job_list->count-1; i++) {
                curr = curr->next;
            }
            curr->next = job_node;//append job to list
        }
        job_list->count += 1;
        printf("[SERVER] Job %d created\n", job_node->pid);
        char job_created[BUFSIZE];
        snprintf(job_created, BUFSIZE, "[SERVER] Job %d created\r\n", job_node->pid);
        write(client->socket_fd, job_created, strlen(job_created));
    }
    else if (res == 0) {//CHILD
        close(stdout_fd[0]);
        close(stderr_fd[0]);//close reading

        char path[BUFSIZE] = JOBS_DIR;
        strncat(path, jobname, strlen(jobname)+1);
        dup2(stdout_fd[1], STDOUT_FILENO);
        dup2(stderr_fd[1], STDERR_FILENO);

        execv(path, args);
        perror("Failed to execute job\r\n");
        exit(1);
    }
    return 0;
}
/* Read message from client and act accordingly.
 * Return their fd if it has been closed or 0 otherwise.
 */
int process_client_request(Client *client, JobList *job_list, fd_set *all_fds) {
    char msg[BUFSIZE];
    if (read_to_buf(client->socket_fd, &(client->buffer)) == 0) {
        return client->socket_fd;
    }
    strncpy(msg, client->buffer.buf, BUFSIZE);
    msg[strcspn(msg, "\n")] = '\0';
    msg[strcspn(msg, "\r")] = '\0';
    printf("[CLIENT %d] %s\n", client->socket_fd, msg);
    memmove(client->buffer.buf, client->buffer.buf+strlen(msg), client->buffer.inbuf);
    
    if (strstr(msg, "jobs") != NULL) {
        write_jobs(client, job_list);
    }
    else if (strstr(msg, "kill") != NULL) {
        kill_job(client, job_list, msg);
    }
    else if (strstr(msg, "run") != NULL) {
        if(job_list->count == MAX_JOBS) {
            printf("%s", MAX_JOBS_UN);
            write(client->socket_fd, MAX_JOBS_NN, strlen(MAX_JOBS_NN));
        }
        else {
            run(msg, client, job_list, all_fds);  
        }
    }
    return 0;
}

/* Return the highest fd between all clients and job pipes.
 */
int get_highest_fd(int listen_fd, Client *clients, JobList *job_list) {
    int max = listen_fd;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].socket_fd > max) {
            max = clients[i].socket_fd;
        }
    }
    if (job_list->count == 0) {
        return max;
    }
    JobNode *curr_job = job_list->first;
    for (int i = 0; i < job_list->count; i++) {
        if (curr_job->stdout_fd > max) {
            max = curr_job->stdout_fd;
        }
        if (curr_job->stderr_fd > max) {
            max = curr_job->stderr_fd;
        }
        curr_job = curr_job->next;
    }
    return max;
}

/* Process output from each child
 * Returns 1 if at least one child exists, 0 otherwise.
 */
int process_jobs(JobList *job_list, fd_set *current_fds, fd_set *all_fds) {
    if(job_list->count == 0) {
        return 0;
    }
    JobNode *curr = job_list->first;
    for (int i = 0; i < job_list->count; i++) {
        if (FD_ISSET(curr->stdout_fd, current_fds)) {
            char *format = "[JOB %d] %s";
            process_job_output(curr, curr->stdout_fd, &(curr->stdout_buffer), format);
        }
        if (FD_ISSET(curr->stderr_fd, current_fds)) {
            char *format = "*(JOB %d)* %s";
            process_job_output(curr, curr->stderr_fd, &(curr->stdout_buffer), format);
        }
        curr = curr->next;
    }
    return 1;
}

void clean_exit(int listen_fd, Client *clients, JobList *job_list, int exit_status) {
    close(listen_fd);//close socket fd

    for (int i = 0; i < MAX_CLIENTS; i++) {//clients
        if (clients[i].socket_fd > -1) {//cant close fd if it = -1
            write(clients[i].socket_fd, "[SERVER] Shutting down\r\n", strlen("[SERVER] Shutting down\r\n"));
            printf("[SERVER] Shutting down\n");
            close(clients[i].socket_fd);//close their fds
        }
    }

    JobNode *curr_job = job_list->first;
    JobNode *prev = curr_job;
    for (int i = 0; i < job_list->count; i++) {
        close(curr_job->stdout_fd);
        close(curr_job->stderr_fd);
        kill(curr_job->pid, SIGKILL);
        curr_job = curr_job->next;
        free(prev->watcher_list.first);
        free(prev);//must also free watcher_list
        prev = curr_job;
    }
    exit(exit_status);
}

int main(void) {
    // Reset SIGINT received flag.
    sigint_received = 0;

    // This line causes stdout and stderr not to be buffered.
    // Don't change this! Necessary for autotesting.
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    //TODO: Set up SIGCHLD handler
    struct sigaction chldact;
    chldact.sa_handler = SIGCHLDhandler;
    chldact.sa_flags = SA_RESTART;
    sigemptyset(&chldact.sa_mask);
    sigaction(SIGCHLD, &chldact, NULL);

    // TODO: Set up SIGINT handler
    struct sigaction intact;
    intact.sa_handler = SIGINThandler;
    intact.sa_flags = SA_RESTART;
    sigemptyset(&intact.sa_mask);
    sigaction(SIGINT, &intact, NULL);

    // TODO: Set up server socket
    struct sockaddr_in *self = init_server_addr(PORT);
    int sockfd = setup_server_socket(self, MAX_CLIENTS);

    // TODO: Initialize client tracking structure (array list)
    Client clients[MAX_CLIENTS];
    for (int index = 0; index < MAX_CLIENTS; index++) {
        clients[index].socket_fd = -1;
    }

    // TODO: Initialize job tracking structure (linked list)
    job_list.first = NULL;
    job_list.count = 0;

    // TODO: Set up fd set(s) that we want to pass to select()
    int max_fd = sockfd;
    FD_ZERO(&all_fds);
    FD_SET(sockfd, &all_fds);
    while (1) {
        // Use select to wait on fds, also perform any necessary checks 
        // for errors or received signals
        listen_fds = all_fds;
        max_fd = get_highest_fd(sockfd, clients, &job_list);
        int nready = select(max_fd + 1, &listen_fds, NULL, NULL, NULL);
        if (nready == -1) {
            if(sigint_received == 1) {
                clean_exit(sockfd, clients, &job_list, 0);
            }
            if (errno == EINTR) {
                continue;
            }
            else {
                perror("server: select");
                exit(1);
            }
        }
        //accept inc. connections

        //original socket
        if (FD_ISSET(sockfd, &listen_fds)) {
            int client_fd = setup_new_client(sockfd, clients);
            if (client_fd < 0) {
                    continue;
            }
            if (client_fd > max_fd) {
                max_fd = client_fd;
            }
            FD_SET(client_fd, &all_fds);
            printf("Accepted connection\n");
        }

        // Check our job pipes, update max_fd if we got children
        //loop through job fds
        max_fd = get_highest_fd(sockfd, clients, &job_list);
        process_jobs(&job_list, &listen_fds, &all_fds);

        // Check on all the connected clients, process any requests
        // or deal with any dead connections etc.
        for (int index = 0; index < MAX_CLIENTS; index++) {
            if (clients[index].socket_fd > -1 && FD_ISSET(clients[index].socket_fd, &listen_fds)) {
                int client_closed = process_client_request(&clients[index], &job_list, &all_fds);
                if (client_closed > 0) {
                    FD_CLR(client_closed, &all_fds); //remove fd from fd set
                    close(client_closed);//close fd
                    clients[index].socket_fd = -1;
                    printf("[CLIENT %d] Connection closed.\n", client_closed);
                } else {
                    
                }
            }
        }
        for (int i = 0; i < pids_index; i++) {
            remove_job(&job_list, pids[i]);
        }

        if (sigint_received == 1) {
            clean_exit(sockfd, clients, &job_list, 0);
        }
    }

    //free(self);
    close(sockfd);
    clean_exit(sockfd, clients, &job_list, 0);
    return 0;
}