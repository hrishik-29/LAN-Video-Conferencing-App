# LAN Video Conferencing Application

This project is a real-time video conferencing tool designed to operate over a Local Area Network (LAN). It was built to demonstrate the practical application of computer networking concepts, specifically the differences between TCP and UDP protocols in a multimedia environment.

The application allows multiple users to connect to a central server, stream video and audio, exchange text messages, and share their screens. It uses a custom-built GUI and a hybrid networking architecture to balance reliability with performance.

## Project Overview

The core challenge in video conferencing is managing two conflicting needs: reliability (for text/commands) and speed (for video/audio). This application solves that by splitting traffic into two distinct channels:

1.  **Control Channel (TCP/SSL):** Used for things that cannot be lost, such as logging in, sending chat messages, or signaling that a user has left. This connection is encrypted using SSL to ensure security.
2.  **Media Channel (UDP):** Used for video frames and audio packets. UDP is connectionless and faster, meaning if a video frame is dropped, the system just moves on to the next one rather than pausing to request it again. This prevents the "lag" often seen in TCP-based streams.

## Technical Architecture

The system is built using Python and relies on the following key libraries:
*   **PyQt6:** Handles the graphical user interface (GUI) for both the client and the server dashboard.
*   **Asyncio:** Powers the server's ability to handle multiple connections simultaneously without blocking.
*   **OpenCV:** Captures video from the webcam, resizes frames, and compresses them into JPEG format for transmission.
*   **PyAudio:** Captures raw audio data from the microphone.

### How It Works

**1. The Server (server.py & server_ui.py)**
The server acts as a relay station. It does not generate media; it simply forwards data.
*   It maintains a registry of active sessions (rooms).
*   It listens on a TCP port for administrative commands (joining/leaving).
*   It listens on two separate UDP ports (one for video, one for audio). When it receives a packet from User A, it looks up who else is in the room and forwards that packet to User B and User C.

**2. The Client (client_gui.py)**
The client is multi-threaded to ensure the interface never freezes.
*   **Video Thread:** Captures a frame, compresses it, adds a header containing the username, and blasts it out via UDP.
*   **Audio Thread:** Uses a "Voice Activity Detection" (VAD) algorithm. It calculates the energy level of the microphone input; if the volume is below a certain threshold (silence), it stops sending data to save bandwidth.
*   **Receiving Threads:** Separate threads listen for incoming data. When video arrives, it is decoded and painted to the screen. When audio arrives, it is put into a "Jitter Buffer" to smooth out playback.

## Installation and Setup

**Prerequisites**
You will need Python 3.10 or higher installed.

**Dependencies**
Install the required Python packages using pip:
pip install PyQt6 opencv-python pyaudio

*Note: On Windows, installing PyAudio can sometimes be difficult. If the standard install fails, try installing `pipwin` first, then use `pipwin install pyaudio`.*

## Usage Instructions

**Step 1: Start the Server**
Run the server interface first. This machine will act as the host.

python server_ui.py:
A dashboard will appear. Click the "Start" button. The dashboard will display the IP address of the server (e.g., 192.168.1.5). You will need this IP for the clients.

**Step 2: Start the Clients**
On the same computer or other computers connected to the same WiFi network, run the client application:

python client_gui.py:
1.  Enter the **Server IP** displayed on the server dashboard.
2.  Enter a **Username** (this will be shown to other users).
3.  Click **Connect**.

Once connected, you should see your own camera feed and the feeds of anyone else connected to the session. You can use the "Share Screen" button to broadcast your desktop to other participants.

## Network Configuration

If you are running this across multiple computers, ensure your Windows Firewall allows Python to communicate on the following ports:
*   **TCP 50001:** Control signals and Chat
*   **UDP 50002:** Video Stream
*   **UDP 50003:** Audio Stream

## Future Improvements

*   **Adaptive Bitrate:** Currently, the video quality is fixed. A future update could lower1.  Enter the **Server IP** displayed on the server dashboard.
2.  Enter a **Username** (this will be shown to other users).
3.  Click **Connect**.

Once connected, you should see your own camera feed and the feeds of anyone else connected to the session. You can use the "Share Screen" button to broadcast your desktop to other participants.

## Network Configuration

If you are running this across multiple computers, ensure your Windows Firewall allows Python to communicate on the following ports:
*   **TCP 50001:** Control signals and Chat
*   **UDP 50002:** Video Stream
*   **UDP 50003:** Audio Stream

## Future Improvements

*   **Adaptive Bitrate:** Currently, the video quality is fixed. A future update could lower the quality automatically if the network becomes slow.
  
*   NAT Traversal: The current version works on LAN. To work over the internet, implementation of STUN/TURN servers would be required to bypass routers.
