#!/usr/bin/php
<?php
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

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();

/*
* read cli parameters
*/
$options = getopt("f:t:p:vi:o:");

$verbose = isset($options['v']) ? true : false;
$from = isset($options['f']) ? trim($options['f']) : '0.0.0.0';
$to = isset($options['t']) ? trim($options['t']) : NULL;
$ports = isset($options['p']) ? array_unique(explode(',', trim($options['p']))) : array();
$inDumpFilePath = isset($options['i']) ? trim($options['i']) : NULL;
$outDumpFilePath = isset($options['o']) ? trim($options['o']) : NULL;


/*
* validate cli parameters
*/
if ($to == NULL) die("missing target ip address parameter -t\n");
if (!filter_var($to, FILTER_VALIDATE_IP)) die("parameter -t is not an ip address\n");
if (!filter_var($from, FILTER_VALIDATE_IP)) die("parameter -f is not an ip address\n");
if (sizeof($ports) == 0) die("missing (comma-separated) ports parameter -p\n");
foreach($ports as $port) {
	if (!is_numeric($port) || $port < 1 || $port > 65535) die("invalid port $port in parameter -p\n");
}
if($inDumpFilePath != NULL && is_file($inDumpFilePath)) die("inbound data dump file already exists\n");
if($outDumpFilePath != NULL && is_file($outDumpFilePath)) die("outbound data dump file already exists\n");


/*
* create dump file handles
*/
$inDumpFileHandle = NULL;
if($inDumpFilePath != NULL) {
	$inDumpFileHandle = fopen($inDumpFilePath, 'ab');
}

$outDumpFileHandle = NULL;
if($outDumpFilePath != NULL) {
	$outDumpFileHandle = fopen($outDumpFilePath, 'ab');
}


/*
* for each port a listening server socket is created 
* and stored under the same key as the port
*/
$serverListeningSocketPorts = array();
$serverListeningSockets = array();


/*
* for each server socket an associated client socket is created  
* and stored under the same key as the server socket
*/
$serverSockets = array();
$clientSockets = array();


/*
* for each port a listening server socket is created
*/
foreach ($ports as $port) {
	// setup listening server socket
	$serverListeningSocket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
	if ($serverListeningSocket === FALSE) {
		logSocketError();
		die();
	}

	if (socket_set_option($serverListeningSocket, SOL_SOCKET, SO_REUSEADDR, 1) === FALSE) {
		logSocketError();
		die();
	}

	if (socket_bind($serverListeningSocket, $from, $port) === FALSE) {
		logSocketError();
		die();
	}

	if (socket_listen($serverListeningSocket) === FALSE) {
		logSocketError();
		die();
	}
	
	$serverListeningSockets[] = $serverListeningSocket;
	
	$keyOfListeningSocket = getKeyOfSocket($serverListeningSocket, $serverListeningSockets);
	assert(!isset($serverListeningSocketPorts[$keyOfListeningSocket]));
	$serverListeningSocketPorts[$keyOfListeningSocket] = $port;
}

// -----------------------------------------------------

$numberOfIdleIterations = 0;

// server loop
while (true) {
	$isIdleIteration = TRUE;

	// accept new sockets
	$isIdleIteration = acceptSockets() && $isIdleIteration;
	
	// server sockets -> client sockets
	$isIdleIteration = copyDataBetweenSockets($serverSockets, $clientSockets, 0) 
			&& $isIdleIteration;
	
	// client sockets -> server sockets
	$isIdleIteration = copyDataBetweenSockets($clientSockets, $serverSockets, 1) 
			&& $isIdleIteration;
	
	// sleep
	if ($isIdleIteration) {
		$numberOfIdleIterations = min($numberOfIdleIterations + 1, 10000);
		
		if ($numberOfIdleIterations > 10) {
			$sleepTimeInMs = min(500, $numberOfIdleIterations);
		
			// if ($verbose) echo "sleeping $sleepTimeInMs ms\n";
			usleep($sleepTimeInMs * 1000);
		}
	}
	else {
		$numberOfIdleIterations = 0;
	}
}

foreach ($serverSockets as $keyOfServerSocket => $serverSocket) {
	disconnectSockets($keyOfServerSocket);
}

// -----------------------------------------------------

function acceptSockets() {
	global $to;
	global $clientSockets;
	global $serverListeningSockets;
	global $serverListeningSocketPorts;
	global $serverSockets;
	global $verbose;
	
	$serverListeningSocketsReadable = $serverListeningSockets;
	$write = NULL;
	$except = NULL;
	
	$isIdle = TRUE;

	// identify active listening server sockets
	if (socket_select($serverListeningSocketsReadable, $write, $except, 0) > 0) {
		$isIdle = FALSE;
	
		// for all active listening server sockets
		foreach ($serverListeningSocketsReadable as $serverListeningSocketReadable) {
			// accept the client
			if ($verbose) echo "accepting new server socket\n";
			$newServerSocket = socket_accept($serverListeningSocketReadable);
			
			if ($newServerSocket === FALSE) {
				logSocketError();
			}
			else {
				// add the new socket to the array of server sockets
				$serverSockets[] = $newServerSocket;
				$keyOfServerSocket = getKeyOfSocket($newServerSocket, $serverSockets);

				// create client socket for the server socket
				if ($verbose) echo "creating client socket for server socket $newServerSocket [$keyOfServerSocket]\n";
				$clientSocket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
				
				if ($clientSocket === FALSE) {
					logSocketError();
					disconnectSockets($keyOfServerSocket);
				}
				else {
					$keyOfListeningSocket = getKeyOfSocket($serverListeningSocketReadable, 
							$serverListeningSockets);
					$portOfInterceptedHost = $serverListeningSocketPorts[$keyOfListeningSocket];
				
					// open connection to intercepted host
					if ($verbose) echo "connecting client socket $clientSocket [$keyOfServerSocket] on port $portOfInterceptedHost\n";
					$success = socket_connect($clientSocket, $to, $portOfInterceptedHost);
					
					if ($success === FALSE) {
						logSocketError();
						disconnectSockets($keyOfServerSocket);	
					}
					else {
						assert(!isset($clientSockets[$keyOfServerSocket]));
						$clientSockets[$keyOfServerSocket] = $clientSocket;
					}
				}
			}
		}
	}
	
	return $isIdle;
}

function copyDataBetweenSockets(&$fromSockets, &$toSockets, $direction) {
	global $verbose;
	global $inDumpFileHandle;
	global $outDumpFileHandle;

	$fromSocketsReadable = $fromSockets;
	$write = NULL;
	$except = NULL;
	
	$isIdle = TRUE;

	// identify active sockets that have data to read
	if (sizeof($fromSocketsReadable) > 0 
			&& socket_select($fromSocketsReadable, $write, $except, 0) > 0) {
		$isIdle = FALSE;
	
		// for all active sockets that have data to read
		foreach ($fromSocketsReadable as $fromSocketReadable) {
			$keyOfSocket = getKeyOfSocket($fromSocketReadable, $fromSockets);

			if ($verbose) echo "reading data from socket $fromSocketReadable [$keyOfSocket]\n";			
			// silence socket_read, as in case of a disconnected remote socket an error is reported
			$binaryData = @socket_read($fromSocketReadable, 4096, PHP_BINARY_READ);

			if ($binaryData === FALSE) {
				logSocketError('socket $fromSocketReadable [$keyOfSocket]');
				disconnectSockets($keyOfSocket);
			}
			else if (empty($binaryData)) {
				if ($verbose) echo "no more data to read from socket $fromSocketReadable [$keyOfSocket]\n";
				disconnectSockets($keyOfSocket);
			}
			else {
				if ($direction === 0 && $outDumpFileHandle != NULL) {
					if ($verbose) echo "logging outbound data to $outDumpFileHandle\n";
					fwrite($outDumpFileHandle, $binaryData);
				}
				else if ($direction === 1 && $inDumpFileHandle != NULL) {
					if ($verbose) echo "logging inbound data to $inDumpFileHandle\n";
					fwrite($inDumpFileHandle, $binaryData);
				}
				
				if ($verbose) echo "writing data to socket $toSockets[$keyOfSocket] [$keyOfSocket]\n";
				$writtenBytes = socket_write($toSockets[$keyOfSocket], $binaryData);
				
				if ($writtenBytes === FALSE) {
				 	logSocketError();
					disconnectSockets($keyOfSocket);
				}
			}
		}
	}
	
	return $isIdle;
}

function disconnectSockets($keyOfServerSocket) {
	global $clientSockets;
	global $serverSockets;
	global $verbose;

	// disconnect client socket, if present
	if (isset($clientSockets[$keyOfServerSocket])) {
		if ($verbose) echo "disconnecting client socket $keyOfServerSocket\n";
		socket_close($clientSockets[$keyOfServerSocket]);
		unset($clientSockets[$keyOfServerSocket]);
	}

	// disconnect server socket, if present
	if (isset($serverSockets[$keyOfServerSocket])) {
		if ($verbose) echo "disconnecting server socket $keyOfServerSocket\n";
		socket_close($serverSockets[$keyOfServerSocket]);
		unset($serverSockets[$keyOfServerSocket]);
	}
}

function getKeyOfSocket($socket, $sockets) {
	return array_search($socket, $sockets);
}

function logSocketError($message = '') {
	echo $message . ' ' . socket_strerror(socket_last_error()). "\n";
}
?>
