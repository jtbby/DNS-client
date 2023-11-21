import struct
import sys
import message
import socket


def send_query(packet):
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket

    clientSocket.settimeout(5)

    for attempt in range(3):
        try:
            clientSocket.sendto(packet.fullQuery, ('8.8.8.8', 53))  # Send the DNS query to the DNS server

            # Receive the DNS response
            response, server_address = clientSocket.recvfrom(1024)  # receive DNS response (bytes object read from an udp socket, and address of client socket as a tuple)

            # Close the socket and return the response
            clientSocket.close()
            print(f"DNS response received (attempt {attempt + 1} of 3)")
            return response

        except socket.timeout:
            print(f"Timeout - Retrying (Attempt {attempt + 1})")

    print("Error: No response received after 3 attempts.")  # If no response is received after 3 attempts, print an error message
    clientSocket.close()

    exit(0) # exit if no response

def receive_response(packet, origpacket):
    headersection = struct.unpack('!HBBHHHH', packet[:12])

    questionOffset = 12  # Question section starts from 12 onwards.

    # Extract ID, QR, OPCODE From Header

    # The follwing code contains alot of bitshifting & masking.
    # Essentially, we unpacked the header portion of the response,
    # and now we are grabbing the values of the bits for each relevant field.

    id = headersection[0]
    qr = (headersection[1] >> 7) & 1
    opCode = (headersection[1] >> 3) & 0xF
    AA = (headersection[1] >> 2) & 1
    TC = (headersection[1] >> 1) & 1
    RD = (headersection[1] & 1)
    RA = (headersection[2] >> 7) & 1
    Z = (headersection[2] >> 4) & 0x7
    rcode = headersection[2]  & 0xF
    qdCount = headersection[3]
    anCount = headersection[4]
    nsCount = headersection[5]
    arCount = headersection[6]

    print(f"header.ID = {id}")
    print(f"header.QR = {qr}")
    print(f"header.OPCODE = {opCode}")
    print(f"header.AA = {AA}")
    print(f"header.TC = {TC}")
    print(f"header.RD = {RD}")
    print(f"header.RA = {RA}")
    print(f"header.Z = {Z}")
    print(f"header.RCODE = {rcode}")
    print(f"header.QDCOUNT = {qdCount}")
    print(f"header.ANCOUNT = {anCount}")
    print(f"header.NSCOUNT = {nsCount}")
    print(f"header.ARCOUNT = {arCount}")

    print("....")
    print("....")

    # Extract QNAME, QTYPE, QCLASS from Question
    for _ in range(qdCount):
        QNAME = []
        i = questionOffset  # start from 12
        while packet[i] != 0:  # Until we reach the start of QTYPE
            i += 1
            currentLabel = packet[i:i + packet[i-1]].decode('ascii')  # python semantics
            QNAME.append(currentLabel)
            i += packet[i-1]  # now we need to advance past the current label


        QNAME = '.'.join(QNAME)
        i += 1

        QTYPE = packet[i] + packet[i+1]
        QCLASS = packet[i+2] + packet[i+3]

        print(f"question.QNAME = {QNAME}")
        print(f"question.QTYPE = {QTYPE}")
        print(f"question.QCLASS = {QCLASS}")

        i += 4  # increment by 4 to go past the QTYPE & QCLASS

    # Above loop will run until based on QDCOUNT


    print("....")
    print("....")

    # Extract Name, Type from Answer

    for _ in range(anCount):
        # answerSection = packet[i:]  # answer should start here

        # same as before, we need to go until we get past the name
        startI = i  # for the name, we will use this later

        while packet[i] != 0: # until we find TYPE
            i += 2

        finishI = i # for the name, we will use this later

        # TYPE, CLASS, TTL, and RDLENGTH are of specific length in our case.
        # Using the position, we grab the necessary amount of bytes from that point on.
        answerbeforeRDATA = struct.unpack('!HHIH', packet[i:i+10])  # TYPE, CLASS, TTL, RDLENGTH

        TYPE = answerbeforeRDATA[0]
        CLASS = answerbeforeRDATA[1]
        TTL = answerbeforeRDATA[2]
        RDLENGTH = answerbeforeRDATA[3]

        # increment past these fields to RDATA
        i += 10

        # resolvedIP = packet[i:i+RDLENGTH] # this is the rest of the resolved IP

        # since type and class are defined, we only have to worry about RDATA in one format

        splitparts = list(packet[i:i+RDLENGTH])  # rest of resolved IP, until finished or next response
        RDATA = ""

        for i in range(len(splitparts)):
            RDATA += str(splitparts[i])
            if i != len(splitparts) - 1:  # except for the last, we want to add a period between each section of the IP.
                RDATA += "."

        print(f"answer.NAME = {packet[startI:finishI].hex()}") # NAME is compressed, so just print the values in hex.
        print(f"answer.TYPE = {TYPE}")
        print(f"answer.CLASS = {CLASS}")
        print(f"answer.TTL = {TTL}")
        print(f"answer.RDLENGTH = {RDLENGTH}")
        print(f"answer.RDATA = {RDATA}")

        print("....")
        print("....")
        i += RDLENGTH  # increment past, in case there are other RR.

    # Above loop will run based on ANCOUNT


    return None

def dns_query():
    if sys.argv[1] is None:
        print("Error no Url")
        exit(0)

    print("Preparing DNS query...")
    print("Contacting DNS server...")
    print("Sending DNS query...")

    packet = message.Message()  # Initialize the message and generate the Header
    packet.Question = message.Question(sys.argv[1])  # Prepare the question field by passing in url
    packet.buildQuery()  # build the full query message since all fields need to be added


    response = send_query(packet) #Send packet to socket.

    print("Processing DNS response")
    print("--------------------------------------------------------")

    receive_response(response, packet) # Receive response. Here we unpack response




if __name__ == '__main__':
    dns_query()
