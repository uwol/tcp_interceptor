/*
 Copyright (C) 2014 u.wol@wwu.de
 
 This file is part of tcp_interceptor.
 
 tcp_interceptor is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 tcp_interceptor is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with tcp_interceptor. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <tgmath.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


struct SocketTuple {
    int serverSocket;
    int clientSocket;
};


bool verbose = false;

char buffer[4096];
char *from = NULL;
char *to = NULL;
int *ports;
int numberOfPorts = 0;
char *inDumpFilePath = NULL;
char *outDumpFilePath = NULL;

struct sockaddr_in from_addr;
struct sockaddr_in to_addr;

int *serverListeningSockets = NULL;

int numberOfSocketTuples = 0;
struct SocketTuple *socketTuples = NULL;

int maxListeningSocket = -1;
int maxInterceptingSocket = -1;
struct timeval timeoutCounter;

FILE* inDumpFileHandle = NULL;
FILE* outDumpFileHandle = NULL;


bool file_exists(const char * filename)
{
    FILE * file = fopen(filename, "r");
    
    if (file)
    {
        fclose(file);
        return true;
    }
    
    return false;
}

struct SocketTuple* findSocketTupleWithSocket(int socket) {
    for (int i = 0; i<numberOfSocketTuples; i++) {
        struct SocketTuple socketTuple = socketTuples[i];
        
        if (socketTuple.serverSocket == socket || socketTuple.clientSocket == socket) {
            return &socketTuples[i];
        }
    }
    
    return 0;
}

struct SocketTuple* acquireSocketTuple() {
    // try to acquire an empty socket tuple
    for (int i = 0; i<numberOfSocketTuples; i++) {
        struct SocketTuple socketTuple = socketTuples[i];
        
        if (socketTuple.serverSocket == 0 && socketTuple.clientSocket == 0) {
            return &socketTuples[i];
        }
    }
    
    // or create a new socket tuple
    struct SocketTuple newSocketTuple = { };
    numberOfSocketTuples++;
    
    socketTuples = realloc(socketTuples, numberOfSocketTuples * sizeof(socketTuples[0]));
    socketTuples[numberOfSocketTuples-1] = newSocketTuple;
    
    return &socketTuples[numberOfSocketTuples-1];
}

int getSocketFromSocketTuple(struct SocketTuple socketTuple, int direction) {
    if (direction == 0) {
        return socketTuple.serverSocket;
    } else if (direction == 1) {
        return socketTuple.clientSocket;
    } else {
        return -1;
    }
}

void closeSocketTuple(struct SocketTuple *socketTuple) {
	// disconnect client socket, if present
	if (socketTuple->clientSocket != 0) {
		if (verbose) printf("disconnecting client socket\n");
		close(socketTuple->clientSocket);
	}
    
	// disconnect server socket, if present
	if (socketTuple->serverSocket != 0) {
		if (verbose) printf("disconnecting server socket\n");
		close(socketTuple->serverSocket);
	}
    
    // clear socket tuple, so it can be reused
    socketTuple->clientSocket = 0;
    socketTuple->serverSocket = 0;
}

void closeSocket(int socket) {
    struct SocketTuple* socketTuple = findSocketTupleWithSocket(socket);
    closeSocketTuple(socketTuple);
}


bool acceptSockets() {
    fd_set serverListeningSocketsReadable;
    
    FD_ZERO(&serverListeningSocketsReadable);
    
    int numberOfServerListeningSockets = sizeof(serverListeningSockets) / sizeof(serverListeningSockets[0]);
    
    for (int i = 0; i < numberOfServerListeningSockets; i++) {
        FD_SET(serverListeningSockets[i], &serverListeningSocketsReadable);
    }
    
	bool isIdle = true;
    
    timeoutCounter.tv_sec = 0;
    timeoutCounter.tv_usec = 0;
    
    // identify active listening server sockets
    int selectResult = select(maxListeningSocket + 1, &serverListeningSocketsReadable, NULL, NULL, &timeoutCounter);
    
    if (selectResult == -1) {
        printf("could not select listening sockets with data\n");
        exit(-1);
    } else if (selectResult > 0) {
		isIdle = false;
        
		// for all active listening server sockets
        for (int i=0; i<numberOfServerListeningSockets; i++) {
            int serverListeningSocket = serverListeningSockets[i];
            
            // if the socket is contained in the set of active sockets
            if (FD_ISSET(serverListeningSocket, &serverListeningSocketsReadable)) {
                int serverListeningSocketReadable = serverListeningSocket;
                
                // accept the client
                if (verbose) printf("accepting new server socket\n");
                
                int newServerSocket = accept(serverListeningSocketReadable, NULL, NULL);
                
                if (newServerSocket < 0) {
                    printf("could not accept new server socket\n");
                }
                else {
                    if (newServerSocket > maxInterceptingSocket) {
                        maxInterceptingSocket = newServerSocket;
                    }
                    
                    struct SocketTuple* newSocketTuple = acquireSocketTuple();
                    newSocketTuple->serverSocket = newServerSocket;
                    
                    // create client socket for the server socket
                    if (verbose) printf("creating client socket for server socket\n");
                    
                    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
                    
                    if (clientSocket < 0) {
                        printf("could not create client socket\n");
                        closeSocket(newServerSocket);
                    }
                    else {
                        if (clientSocket > maxInterceptingSocket) {
                            maxInterceptingSocket = clientSocket;
                        }
                        
                        // init port of target socket
                        int serverListeningSocketPort = ports[i];
                        to_addr.sin_port = htons(serverListeningSocketPort);
                        
                        // open connection to intercepted host
                        if (verbose) printf("connecting client socket \n");
                        
                        int rc = connect(clientSocket, (struct sockaddr *) &to_addr, sizeof(to_addr));
                        
                        if (rc < 0) {
                            closeSocket(newServerSocket);
                        }
                        else {
                            newSocketTuple->clientSocket = clientSocket;
                        }
                    }
                }
            }
        }
	}
	
	return isIdle;
}

bool copyDataBetweenSockets(int direction) {
    fd_set fromSocketsReadable;
    
    FD_ZERO(&fromSocketsReadable);
    
    for (int i = 0; i < numberOfSocketTuples; i++) {
        struct SocketTuple socketTuple = socketTuples[i];
        
        int socket = getSocketFromSocketTuple(socketTuple, direction);
        if(socket != 0){
            FD_SET(socket, &fromSocketsReadable);
        }
    }
    
    bool isIdle = true;
    
    timeoutCounter.tv_sec = 0;
    timeoutCounter.tv_usec = 0;
    
    // identify active sockets that have data to read
    int selectResult = select(maxInterceptingSocket + 1, &fromSocketsReadable, NULL, NULL, &timeoutCounter);
    
    if (selectResult == -1) {
        printf("could not select intercepting sockets with data\n");
        exit(-1);
    }
    else if (selectResult > 0) {
        isIdle = false;
        
        // for all active sockets that have data to read
        for (int i=0; i<numberOfSocketTuples; i++) {
            struct SocketTuple socketTuple = socketTuples[i];
            int socket = getSocketFromSocketTuple(socketTuple, direction);
            
            // if the socket is contained in the set of active sockets
            if (FD_ISSET(socket, &fromSocketsReadable)) {
                int fromSocketReadable = socket;
                
                if (verbose) printf("reading data from socket\n");
                
                long receivedChars = recv(fromSocketReadable, buffer, sizeof(buffer), 0);
                
                if (receivedChars < 0) {
                    printf("error when reading data from socket\n");
                    closeSocket(fromSocketReadable);
                }
                else if (receivedChars == 0) {
                    if (verbose) printf("no more data to read from socket\n");
                    closeSocket(fromSocketReadable);
                }
                else {
                    if (verbose) printf("writing data to socket\n");
                    
                    struct SocketTuple *socketTuple = findSocketTupleWithSocket(fromSocketReadable);
                    
                    long sentChars;
                    
                    if (socketTuple->clientSocket == fromSocketReadable) {
                        if (inDumpFileHandle != NULL) {
                            if (verbose) printf("logging inbound data\n");
                            fwrite(buffer, 1, receivedChars, inDumpFileHandle);
                        }
                        
                        sentChars = send(socketTuple->serverSocket, buffer, receivedChars, 0);
                    }
                    else {
                        if(outDumpFileHandle != NULL) {
                            if (verbose) printf("logging outbound data\n");
                            fwrite(buffer, 1, receivedChars, outDumpFileHandle);
                        }
                        
                        sentChars = send(socketTuple->clientSocket, buffer, receivedChars, 0);
                    }
                    
                    if (sentChars < 0) {
                        closeSocket(fromSocketReadable);
                    }
                }
            }
        }
    }
    
    return isIdle;
}


int main (int argc, char *argv[])
{
    int c;
    char* currentPortChars;
    
    /*
     * read cli parameters
     */
    while ((c = getopt (argc, argv, "f:t:p:vi:o:")) != -1) {
        switch (c)
        {
            case 'v':
                verbose = true;
                break;
            case 'f':
                from = optarg;
                break;
            case 't':
                to = optarg;
                break;
            case 'p':
                currentPortChars = strtok(optarg, ",");
                
                ports = NULL;
                
                while (currentPortChars != NULL)
                {
                    ports = realloc(ports, (numberOfPorts+1) * sizeof(int));
                    ports[numberOfPorts] = (int) strtol(currentPortChars, NULL, 10);
                    currentPortChars = strtok(NULL, ",");
                    numberOfPorts++;
                }
                break;
            case 'i':
                inDumpFilePath = optarg;
                break;
            case 'o':
                outDumpFilePath = optarg;
                break;
        }
    }
    
    /*
     * validate cli parameters
     */
    if (to == NULL || strlen(to) == 0) {
        printf("missing target ip address parameter -t\n");
        exit(-1);
    }
    
    if (ports == NULL || sizeof(&ports) == 0) {
        printf("missing (comma-separated) ports parameter -p\n");
        exit(-1);
    }
    
    if (inDumpFilePath != NULL && file_exists(inDumpFilePath)) {
        printf("inbound data dump file already exists\n");
        exit(-1);
    }
    
    if (outDumpFilePath != NULL && file_exists(outDumpFilePath)) {
        printf("outbound data dump file already exists\n");
        exit(-1);
    }
    
    for (int i = 0; i<numberOfPorts; i++) {
        int port = ports[i];
        
        if (port < 1 || port > 65535) {
            printf("invalid port $port in parameter -p\n");
            exit(-1);
        }
    }
    
    /*
     * init target address
     */
    memset(&to_addr, 0, sizeof(to_addr));
    to_addr.sin_family = AF_INET;
    
    // parse target address string into address struct
    if (inet_aton(to, &to_addr.sin_addr) < 1) {
        printf("parameter -t is not an ip address\n");
        exit(-1);
    }
    
    
    /*
     * init listening address
     */
    memset(&from_addr, 0, sizeof(from_addr));
    from_addr.sin_family = AF_INET;
    
    if (from != NULL) {
        // parse target address string into address struct
        if (inet_aton(from, &from_addr.sin_addr) < 1) {
            printf("parameter -f is not an ip address\n");
            exit(-1);
        }
    }
    else {
        from_addr.sin_addr.s_addr = INADDR_ANY;
    }
    
    /*
     * create dump file handles
     */
    if (inDumpFilePath != NULL) {
        inDumpFileHandle = fopen(inDumpFilePath, "ab");
    }
    
    if (outDumpFilePath != NULL) {
        outDumpFileHandle = fopen(outDumpFilePath, "ab");
    }
    
    /*
     * for each port a listening server socket is created
     */
    for (int i=0; i<numberOfPorts; i++) {
        serverListeningSockets = realloc(serverListeningSockets, (i+1) * sizeof(int));
        
        int port = ports[i];
        
        // setup listening server socket
        int serverListeningSocket = socket(AF_INET, SOCK_STREAM, 0);
        
        if (serverListeningSocket > maxListeningSocket) {
            maxListeningSocket = serverListeningSocket;
        }
        
        if (serverListeningSocket < 0) {
            printf ("%s\n", strerror(errno));
            exit(-1);
        }
        
        // allow port numbers to be reused
        int optval = 1;
        if (setsockopt(serverListeningSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
            printf ("%s\n", strerror(errno));
            exit(-1);
        }
        
        // set port
        from_addr.sin_port = htons(port);
        
        // bind socket
        if (bind(serverListeningSocket, (struct sockaddr *)&from_addr, sizeof(from_addr)) < 0) {
            printf ("%s\n", strerror(errno));
            close(serverListeningSocket);
            exit(-1);
        }
        
        // listen with queue size 32
        if (listen(serverListeningSocket, 32) < 0) {
            printf ("%s\n", strerror(errno));
            close(serverListeningSocket);
            exit(-1);
        }
        
        // store listening socket
        serverListeningSockets[i] = serverListeningSocket;
    }
    
    
    // -----------------------------------------------------
    
    int numberOfIdleIterations = 0;
    
    // server loop
    while (true) {
        bool isIdleIteration = true;
        
        // accept new sockets
        isIdleIteration = acceptSockets() && isIdleIteration;
        
        // server sockets -> client sockets
        isIdleIteration = copyDataBetweenSockets(0) && isIdleIteration;
        
        // client sockets -> server sockets
        isIdleIteration = copyDataBetweenSockets(1) && isIdleIteration;
        
        // sleep
        if (isIdleIteration) {
            numberOfIdleIterations = fmin(numberOfIdleIterations + 1, 10000);
            
            if (numberOfIdleIterations > 10) {
                int sleepTimeInMs = fmin(500, numberOfIdleIterations);
                
                // if ($verbose) echo "sleeping $sleepTimeInMs ms\n";
                usleep(sleepTimeInMs * 1000);
            }
        }
        else {
            numberOfIdleIterations = 0;
        }
    }
}
