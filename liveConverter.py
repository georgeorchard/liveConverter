#from bitstring import BitArray
from sys import argv
import struct
import base64
import sys
import binascii
import subprocess
import io
import os
from datetime import datetime
import xml.etree.ElementTree as ET
#import hexdump
import pkgutil
import socket
import time

applicationVersionNumber = "1.2.1"
version_count=1
cont_count = 1

def calculate_section_crc(section):
    """
    A function that calculates the CRC of a section
    
    Parameters:
    section (string): String of Hex Bytes
    
    Returns:
    int: 32-bit integer of the CRC value
    """

    # Convert section from hex string to bytes
    section_bytes = section # bytes.fromhex(section)
    
    # Initialize the CRC value
    crc = 0xFFFFFFFF

    # CRC-32 polynomial
    polynomial = 0x04C11DB7

    # Calculate the CRC
    for byte in section_bytes:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc <<= 1
                crc ^= (-1 & polynomial)
            else:
                crc <<= 1
    
    # Convert the CRC value to hex string
    crc_hex = hex(crc & 0xFFFFFFFF)[2:].zfill(8).upper()
    #print ("Calculated CRC:", crc_hex)
    return (crc & 0xFFFFFFFF)
    

        
        
        
        

def sendStuffedPacket(output_stream):
    """
    A function to send a stuffed packet to an Output Stream
    
    Parameters:
    output_stream (file): The output stream
    
    Returns:
    null
    """
    stuffed_packet = bytes ([0x47])
    stuffed_packet += b'\x1F\xFF\x10'
    stuffed_packet += b'\xFF' * 184
    output_stream.write(stuffed_packet) 
    
    
    
    
    
    

def extractSCTEInformation(scte35_payload):
    """
    A function to print data about the SCTE35 payload.
    
    Parameters:
    scte35_payload (packet[]): The payload of SCTE35
    
    Returns:
    null
    """
    res = ''.join(format(x, '02x') for x in scte35_payload)
    """
    print("SCTE-35 Hex:", res)
    print("Splice Payload Len:", scte35_payload[3])
    print("Splice Message Len:", scte35_payload[13])
    print("Splice Message Type:", scte35_payload[14])
    print("Splice Event ID:", struct.unpack('>L', scte35_payload[15:19])[0] & 0xFFFFFFFF)
    print("Splice PTS Time:", scte35_payload[21] & 0x01, " ", struct.unpack('>L', scte35_payload[22:26])[0] & 0xFFFFFFFF)
    print("Splice Duration:", (struct.unpack('>L', scte35_payload[27:31])[0] & 0xFFFFFFFF)/90000)                  
    print("Program ID:", (struct.unpack('>H', scte35_payload[31:33])[0] & 0xFFFF))  
    """    
    

    
    
    
    
def buildDSMCCPacket(scte35_payload, version_count, packet, cont_count):
    """
    Function to build a DSMCC Payload from the SCTE Payload
    
    Arguments:
    scte35_payload (packet[]): The payload packets of the SCTE35
    version_count (int): The version of the DSMCC payload
    packet (packet): The SCTE35 packet.
    cont_count (int): The continuity counter.
    
    Returns:
    Byte[]: DSMCC Packet
    """
    """
    print("v "+ str(version_count))
    print("c "+str(cont_count))
    """
    #print ("\nBuilding Descriptor with SCTE payload")
    
    
    #DESCRIPTOR LIST SECTION - SPLICE INFORMATION - [A178-1r1_Dynamic-substitution-of-content  Table 3] - This information just goes before the SCTE35 data

    #24 bits
    #8 bits: DVB_data_length
    #3 bits: reserved for future use
    #1 bit: event type
    #4 bits: timeline type
    #8 bits: private data length
    dsm_descriptor = bytes ([
    0x01   ,             # length of header
    0xE1 ,                # RRR/Event type 0/ timeline type 0001
    0                 # length of private dats
    ])
    #add the SCTE35 payload to the private data byte
    dsm_descriptor += scte35_payload

    # Base64 encode the SCTE35 payload
    encoded_payload = base64.b64encode(dsm_descriptor) 


   
    
    
    #DATA IN BEFORE DSMCC SECTION FORMAT - STREAM DATA
    #8 bits
    dsmcc_packet = bytes ([0x47])
    
    #Next 16 bits from the packet, contains:
    dsmcc_packet += packet [1:3]
    #print(packet[1:3])
    
    #8 bits
    byte4 = cont_count | 0x10
    dsmcc_packet += byte4.to_bytes (1, 'big')
    
    
    
    
    
    #DSMCC PACKET SECTION - [ISO/IEC 13818-6:1998  Table 9-2]
    
    #Length of DSM-CC Packet
    #4 is the data that goes in before the table_id (stream data)
    
    #6 (should be 5) as this is the data after the dsmcc_section_length field and before we put the dsmcc descriptor field in
    #encoded payload is the splice information from SCTE35
    #4 (should be 12) as this is the length of the streamEventDescriptor without the private data bytes)
    
    #8 is the CRC_32
    
    #dsmcc_len = 6 + len (encoded_payload) + 4 + 8 + 4   
    dsmcc_len = len(encoded_payload) + 4 + 5 + 12 + 8
    
    # 8 bits - Table ID
    # x3D means that section contains stream descriptors - [ISO/IEC 13818-6:1998  Table 9-3]
    #dsmcc_packet += b'\x00\x3D'  
    dsmcc_packet += b'\x3D' 
    
    
    #8 bits
    #1 bit: section_syntax_indicator
    #1 bit: private_indicator
    #2 bits: reserved
    #4 bits: start of DSMCC_section_length (length of everything after this field)
    dsmcc_siglen = dsmcc_len - 1
    dsmcc_packet += (((dsmcc_siglen & 0x0F00) >> 8) + 0xB0).to_bytes (1, 'big')
    
    #8 bits - rest of DSMCC_section_length
    dsmcc_packet += (dsmcc_siglen & 0x00FF).to_bytes (1, 'big')
    
    
    # TID Ext, do-it-now       ETSI TS 102 809 V1.2.1 / Section B32.  TID Ext = EventId 1 (14 bits), Bits 14/15 zero = 0x0001
    #16 bits - table_id_extension (do-it-now)
    dsmcc_packet += b'\x00\x01'
    
    
    # Version 1 (RR/VVVVV/C)   RR / 5 BIts of Version number / Current/Next indicator (always 1)   Version 1 = 11000011 = C3
    #Mask version count to 5 bits so cycles round.
    version_count = version_count & 0b11111
    version_field = 0xC0 + (version_count << 1 ) + 0x01  # Build RR/VVVVV/C
    
    #8 bits 
    #2 bits: reserved
    #5 bits: version_number
    #1 bit: current_next_indicator
    dsmcc_packet += (version_field & 0x00FF).to_bytes (1, 'big')
    #dsmcc_packet += b'\xC3'
    
   
    #16 bits 
    #8 bits: section
    #8 bits: last section
    dsmcc_packet += b'\x00\x00'

    
    
    
    #STREAM EVENT DESCRIPTOR SECTION - [ISO/IEC 13818-6:1998  Table 8-6]
    #8 bits - descriptorTag - x1a = 26 which is Stream Event Descriptor
    dsmcc_packet += b'\x1a'
    
    #8 bits - Descriptor length (think this should be 10 + len(encoded_payload))
    dsmcc_payload_len = len (encoded_payload) + 4
    dsmcc_packet += (dsmcc_payload_len & 0x00FF).to_bytes (1, 'big') 
    
    
    #80 bits - rest of descriptor
    #16 bits: eventID
    #31 bits: reserved
    #33 bits: eventNPT
    dsmcc_packet += b'\x00\x01\xFF\xFF\xFF\xFE\x00\x00\x00\x00'

    #THE PRIVATE DATA BYTES THE SCTE SECTION - Add the SCTE35 payload into the DSMCC Packet
    dsmcc_packet += encoded_payload # DSM-CC Descriptor - SCTE35 payload
    
    
    
    #32 Bits - The CRC_32 Section as sectionSyntaxIndicator == 1 FINAL PART FROM [ISO/IEC 13818-6:1998  Table 9-2]
    dsmcc_crc = calculate_section_crc (dsmcc_packet [5:(dsmcc_len + 3)])                
    dsmcc_packet += dsmcc_crc.to_bytes (4, 'big')

    #Padding to make the packet it 188 bits.
    dsmcc_packet += b'\xFF' * (188-len (dsmcc_packet))

    return(dsmcc_packet)

    

    
   


def find_pmt_pid(pat_data, target_service):
    """
    A function to find the PID of a PMT entry for a specific service.

    Parameters:
    pat_data(list): The list of elements from the PAT.
    target_service(int): The service number to search for.

    Returns:
    pmt_pid(int): The PID of the PMT entry for the target service, or None if not found.
    """
    pmt_pid = None
    looking_for_service = False

    for i, line in enumerate(pat_data):
        if f"Service: {target_service}" in line:
            looking_for_service = True
            # Extract the PID from the previous line (i-1)
            previous_line = pat_data[i - 1]
            if looking_for_service and "PMT" in previous_line:
         
                parts = previous_line.split()
                for j, part in enumerate(parts):
                    if part == "PID:" and j + 1 < len(parts):
                        pid_hex = parts[2]
                        
                        pmt_pid = int(pid_hex, 16)  # Convert hexadecimal to decimal
                        break

    return pmt_pid











def replace_table(input_file, pid, tablexml, output_file):
    """
    Replace tables in the input file with the specified table XML.

    Parameters:
    input_file (str): The input file.
    pid (int): The PID to replace the table.
    tablexml (str): The table XML to inject.
    output_file (str): The output file.

    Returns:
    None
    """
    cmd = [
        'tsp',
        '-I', 'file', input_file,
        '-P', 'inject',
        '-p', str(pid),
        '-r', tablexml,
        '-O', 'file', output_file
    ]
    subprocess.run(cmd, check=True)





def findAvailablePIDs(pmtPID):
    """
    A function to find the best PID for the AIT 
    
    Parameters:
    pmt_pid(string): The hex of the PMT PID
    
    Returns:
    pid(int): The PID to use for the AIT.
    """
    intPID = int(str(pmtPID), 16)
    #Get list of all PIDs
    pids = []

    # Parse the XML file
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    # Find all metadata elements
    metadata_elements = root.findall(".//metadata")

    # Extract PID values and add them to the list
    for metadata_element in metadata_elements:
        pid = metadata_element.attrib.get("PID")
        if pid is not None:
            pid = int(pid.replace(',', ''))
            pids.append(int(pid))
    
    if (intPID+1) in pids:
        # Get nearest PID over 891
        found = false
        i = 891
        while found == false:
            if i in pids:
                i+=1
            else: 
                found = true
                return i
    else:
        return(intPID+1)
        
            
            
       
    

  
  
 
def replaceSCTEElement(xml_file, scte_pid):
    """
    Function to replace a component element in the PMT XML with a specified elementary_PID.
    
    Parameters:
    xml_file (str): The file containing the XML for the PMT.
    scte_pid (str): The hex PID for the component to be replaced.
    """
    
    # Parse the XML file with ElementTree
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Find the PMT element within the root
    pmt_element = root.find(".//PMT")

    if pmt_element is not None:
        # Find the specific component element with the given elementary_PID (scte_pid)
        target_component = pmt_element.find(f".//component[@elementary_PID='{scte_pid}']")

        if target_component is not None:
            # Create the new component element structure
            new_component = ET.Element("component", elementary_PID=scte_pid, stream_type="0x0C")
            ET.SubElement(new_component, "stream_identifier_descriptor", component_tag="0x09")
            ET.SubElement(new_component, "data_stream_alignment_descriptor", alignment_type="0x09")

            # Find the index of the target component and insert the new component before it
            target_index = list(pmt_element).index(target_component)
            pmt_element.insert(target_index, new_component)

            # Remove the target component
            pmt_element.remove(target_component)

            # Save the modified XML
            tree.write(xml_file, encoding="utf-8", xml_declaration=True)
        else:
            print(f"Component with elementary_PID '{scte_pid}' not found in the XML.")
    else:
        print("PMT element not found in the XML.")

    
    
    
 

def addDSMCCComponentElement(xml_file, pid):
    """
    Function to add a new component element within the existing PMT XML using xml.etree.ElementTree.
    
    Parameters:
    xml_file (str): The file containing the XML for the PMT.
    pid (str): The hex PID for the new component element.
    """
    
    # Parse the XML file with ElementTree
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Find the PMT element within the root
    pmt_element = root.find(".//PMT")

    if pmt_element is not None:
        new_component = ET.Element("component", elementary_PID=pid, stream_type="0x0C")
        ET.SubElement(new_component, "stream_identifier_descriptor", component_tag="0x09")
        ET.SubElement(new_component, "data_stream_alignment_descriptor", alignment_type="0x09")
        # Add the new component to the PMT
        pmt_element.append(new_component)


        # Save the modified XML
        tree.write(xml_file, encoding="utf-8", xml_declaration=True)
    else:
        print("PMT element not found in the XML.")
        
            
         


def createAITXML(applicationID, organizationID, url, applicationProfile, applicationVersion, applicationName, initialPath):
    # Create the root element
    root = ET.Element("tsduck")

    # Create the AIT element with attributes
    ait = ET.SubElement(root, "AIT")
    ait.set("application_type", "0x0010")
    ait.set("current", "true")
    ait.set("test_application_flag", "false")
    ait.set("version", "1")
    
    
    

    # Create the application element
    application = ET.SubElement(ait, "application")
    application.set("control_code", "0x01")

    # Create the application_identifier element
    app_identifier = ET.SubElement(application, "application_identifier")
    app_identifier.set("application_id", f"{applicationID}")
    app_identifier.set("organization_id", f"{organizationID}")
    

    # Create the transport_protocol_descriptor element
    tp_descriptor = ET.SubElement(application, "transport_protocol_descriptor")
    tp_descriptor.set("transport_protocol_label", "0x01")

    # Create the http element
    http = ET.SubElement(tp_descriptor, "http")

    # Create the url element with the 'base' attribute
    url_element = ET.Element("url", base=url)

    # Append the url element to the http element
    http.append(url_element)

    # Create the application_descriptor element
    app_descriptor = ET.SubElement(application, "application_descriptor")
    app_descriptor.set("application_priority", "1")
    app_descriptor.set("service_bound", "true")
    app_descriptor.set("visibility", "3")
    
    

    # Create the profile element
    profile = ET.SubElement(app_descriptor, "profile")
    profile.set("application_profile", f"{applicationProfile}")
    profile.set("version", f"{applicationVersion}")
    
    

    # Create the transport_protocol element
    transport_protocol = ET.SubElement(app_descriptor, "transport_protocol")
    transport_protocol.set("label", "0x01")

    # Create the application_name_descriptor element
    app_name_descriptor = ET.SubElement(application, "application_name_descriptor")

    # Create the language element
    language = ET.SubElement(app_name_descriptor, "language")
    language.set("application_name", f"{applicationName}")
    language.set("code", "eng")
    

    # Create the simple_application_location_descriptor element
    location_descriptor = ET.SubElement(application, "simple_application_location_descriptor")
    location_descriptor.set("initial_path", f"{initialPath}")

    # Create an ElementTree object with the root element
    tree = ET.ElementTree(root)

    # Save the XML to a file
    tree.write("aitXML.xml")











def getSCTEPID(fileName):
    """
    A function to get the SCTE PID from the PMT
    
    Parameters:
    fileName(string): The name of the file
    
    Returns:
    scte_pid(String): The SCTE PID
    """
    tree = ET.parse(fileName)
    root = tree.getroot()

    # Find the PMT tag
    pmt_tag = root.find(".//PMT")

    if pmt_tag is not None:
        # Find the component with the specified stream type
        component_tag = pmt_tag.find(f"./component[@stream_type='0x86']")

        if component_tag is not None:
            # Extract the elementary PID from the component
            elementary_pid = component_tag.attrib.get("elementary_PID")
            return elementary_pid

    return None







                
                        
                
                
def getXML(input_file):
    """
    A function to get the XML given a PID
    
    Parameters:
    input_file(String): The input file
    
    Returns:
    null
 
    """
    command = ['tsp', '-I', 'file', input_file, '-P', 'psi', '-x', "dataXML.xml", '-d']
       
       
      
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        """
        # Check for errors
        if process.returncode != 0:
            print(f"Error executing TSDuck command: {error.decode()}")
        else:
            with open(output_file, 'wb') as binary_output:
                binary_output.write(output)
        """
           
    except Exception as e:
        print(f"An error occurred: {e}")
        
     





def get_service_name(target_service_id):
    """
    Function to get the service name based on the service number
    
    Parametes:
    target_service_id(String): The service ID
    
    Returns:
    service_name(String): The name of the service
    """
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    for sdt in root.iter('SDT'):
        for service in sdt.iter('service'):
            service_id = service.attrib.get('service_id')

            if service_id == target_service_id:
                service_name = None
                for descriptor in service.iter('service_descriptor'):
                    service_name = descriptor.attrib.get('service_name')

                return service_name

    return None






def save_pmt_by_service_id(xml_file, service_id):
    """
    Save the PMT tag with the provided service ID to the same XML file.

    Parameters:
    xml_file (str): The path to the XML file.
    service_id (str): The service ID to search for.

    Returns:
    None
    """
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    matching_pmts = []

    # Iterate through PMT tags and find the one with the matching service ID
    for pmt in root.findall(".//PMT"):
        if pmt.attrib.get("service_id") == service_id:
            matching_pmts.append(pmt)

    # Create a new XML tree with the matching PMT tags
    new_root = ET.Element("tsduck")
    new_root.extend(matching_pmts)
    new_tree = ET.ElementTree(new_root)

    # Save the new XML tree to the original XML file
    with open(xml_file, 'wb') as output_file:
        new_tree.write(output_file, encoding="utf-8", xml_declaration=True)



def save_pat():
    """
    Save the PAT tag to the same XML file.

    Parameters:
    None

    Returns:
    None
    """
    tree = ET.parse("dataXML.xml")
    root = tree.getroot()

    matching_pats = []

    # Iterate through PMT tags and find the one with the matching service ID
    for pat in root.findall(".//PAT"):
        matching_pats.append(pat)

    # Create a new XML tree with the matching PMT tags
    new_root = ET.Element("tsduck")
    new_root.extend(matching_pats)
    new_tree = ET.ElementTree(new_root)

    # Save the new XML tree to the original XML file
    with open("patXML.xml", 'wb') as output_file:
        new_tree.write(output_file, encoding="utf-8", xml_declaration=True)







     
      
            

def serviceChoice():
    tree = ET.parse("patXML.xml")
    root = tree.getroot()
    servicesList = []

    pat_info = root.find(".//PAT")
    if pat_info is not None:
        services = pat_info.findall(".//service")

        for index, service in enumerate(services):
            service_id = service.get("service_id")
            program_map_pid = service.get("program_map_PID")
            serviceName = get_service_name(service_id)
            servicesList.append([service_id, program_map_pid, serviceName])
            print(f"Index: {index}, Service ID: {service_id}, Program Map PID: {program_map_pid}, Service Name: {serviceName}")
            
        # Choose the service        
        choice = int(input("Enter the index of the service: "))
        if(choice>=0 and choice < len(services)):
            serviceChoice = servicesList[choice][0]
            pmtChoice = servicesList[choice][1]
            serviceName = servicesList[choice][2]
            return([serviceChoice, pmtChoice, serviceName])



   

def copy_ts_file(source_file, destination_file):
    """
    A function to copy the contents of a TS file to another
    
    Parameters:
    source_file(String): The file to be copied
    destination_file(String): The file to be copied to
    
    Returns:
    None
    """
    try:
        with open(source_file, 'rb') as source, open(destination_file, 'wb') as destination:
            # Read and copy the contents of the source TS file
            while True:
                chunk = source.read(4096)  # Read in chunks
                if not chunk:
                    break
                destination.write(chunk)  # Write the chunk to the destination TS file
        #print(f"Contents from '{source_file}' copied to '{destination_file}' successfully.")
    except FileNotFoundError:
        print("File not found error.")
    except Exception as e:
        print(f"An error occurred: {e}")


        
      

def check_tsduck_version():
    """
    A function to check the TS Duck version on the path
    
    Parameters:
    None
    
    Returns:
    None
    """
    try:
        # Run the 'tsversion' command and capture the output
        result = subprocess.run(['tsversion'], capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()
        #print(result)

        # Check if the first line contains a number
        if output_lines and output_lines[0].strip().isdigit():
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        # If the 'tsversion' command fails or isn't found, return False
        print(f"Error: {e}")
        return False



def convertSCTE(packet, replaceNull, function, sctePids, scteCont):
    """
    A function to convert SCTE to DSMCC given a SCTE packet
    Parameters:
    packet(bytes[]): The SCTE Packet
    replaceNull(Boolean): Replacing nulls
    function(int): The function
    sctePid(int): The scte pid
    scteCont(int): The cont
    Returns
    packet(byte[]): The DSMCC Packet
    """
    global version_count
    global cont_count
    adaptation_len=0
    # Extract packet PID
    pid = struct.unpack('>H', packet[1:3])[0] & 0x1FFF
    #print(pid)
    cc =  struct.unpack('>B', packet[3:4])[0] & 0xFF

    # Check if the packet contains SCTE35 payload
    if pid in sctePids and packet[3] & 0x10:
    
        #print(f"SCTE!")
        # Extract SCTE35 payload
        if packet [3] & 0x30 == 0x30:
            adaptation_len = packet [4] + 1
        scte35_length = packet[7+adaptation_len]
        #print(f"\nAdaption: {adaptation_len}")
        #print(f"SCTE: {scte35_length}")
        scte35_payload = packet[4+adaptation_len:4+scte35_length+4+adaptation_len]
        if scte35_length != 17:
            
            #print("\nSCTE-35 Payload found in packet :", packetcount)
            #print("SCTE-35 Length :", scte35_length)
            #Extract SCTE35 information
            extractSCTEInformation(scte35_payload)
            #Create DSMCC packet
            dsmcc_packet = buildDSMCCPacket(scte35_payload, version_count, packet, scteCont)
            """
            #Update cont_count
            cont_count += 1
            cont_count &= 0x0F
            """
            #events_replaced += 1
            
            # Write the DSM-CC packet to the output stream
            
            """
            
            section = '4740CB15003DB0490001C300001A3E0001FFFFFFFE0000000065794A6A623231745957356B496A6F67496E42795A574A315A6D5A6C6369497349434A786369493649475A6862484E6C66513D3D5852E0BCFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
            dsmcc_packet = bytes.fromhex(section)
            """
            #if version_count == 3:
            #print ("\nWriting replacement packet:", packetcount)
            #output_stream.write(dsmcc_packet)
            version_count += 1
            print(f"DSMCC Packet Replacement for SCTE35 message on PID {pid} written to file (SCTE35 Continuity Counter {scteCont})")
            return(dsmcc_packet)
            
            
        #If SCTE is null    
        else:
            
            #If replaceNUll is true or false
            if replaceNull==False:
                #Not converting null splice into DSM-CC
                #print ("SCTE Detected, len 17")
                #events_notreplaced +=1
                #SEND STUFFED PACKET
                #return stuffed packet
                stuffed_packet = bytes ([0x47])
                stuffed_packet += b'\x1F\xFF\x10'
                stuffed_packet += b'\xFF' * 184
                return(stuffed_packet)
                
                #sendStuffedPacket(output_stream)
            
            else:
                #Still converting null splice into DSM-CC
                #Create DSMCC packet
                dsmcc_packet = buildDSMCCPacket(scte35_payload, version_count, packet, scteCont)
                """
                #Update cont_count
                cont_count += 1
                cont_count &= 0x0F
                """
                #events_replaced += 1
                #output_stream.write (dsmcc_packet)
                print(f"DSMCC Packet Replacement for NULL SCTE35 message on PID {pid} written to file (SCTE35 Continuity Counter {scteCont})")
                return(dsmcc_packet) 
    else:
        #output_stream.write (packet)
        if(function == 0):
            return(packet)
        else:
            #return empty packet if 
            return(bytearray())
    #packetcount +=1
    

def processStream(ip, port, ip2, port2):
    """
    A function to process the stream.
    Parameters:
    ip(String): The IP to listen on
    port(int): The Port to listen on
    ip2(String): The IP to send on
    port2(int): The port to send on
    Returns:
    None
    """
    #connect to the socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    
    command = f"tsp -I ip {port}"
    #command = f"tsp -I ip 5167"
    
    
    command2 = f"tsp -I file -i \"singlePacketFile.ts\" -O ip {ip2}:{port2}"
    
    
    #command3 = "tsp -I ip 5167 -P until --packets 1000000 -O file \"first10Secs.ts\""
    #command3 = f"tsp -I ip {port} -P until --packets 100000 -O file \"first10Secs.ts\""
    #command3 = "tsp -I ip 5167 -P until --seconds 10 -O file \"first10Secs.ts\""
    command3 = f"tsp -I ip {port} -P until --seconds 1 -O file \"first10Secs.ts\""
    
    command4 = f"tsp -I file -i \"singlePMT.ts\" -O ip {ip2}:{port2}"
   
    #give options
    print("\nChoose Function")
    print("0: Output original service with converted SCTE and modified PMT")
    print("1: Output just DSMCC and PMT")
    function = int(input("Enter index of choice: "))
    
    print("\nReplace NULL SCTE?")
    print("0: No")
    print("1: Yes")
    nullChoice = int(input("Enter index of choice: "))
    if nullChoice == 0:
        nullChoice = False
    if nullChoice == 1:
        nullChoice = True
    #find services
    
    #READ FOR X SECONDS AND THEN DO NORMAL FUNCTIONS
    
    process3 = subprocess.Popen(command3, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, bufsize=0)
    time.sleep(1.5)
    getXML("first10Secs.ts")
    save_pat()
    
    #Get data about service chosen
    #multiple services
    serviceCounter = 0
    
    #need an array that stores PIDs against service numbers
    pmtPIDs = []
    sctePIDs = []
    
    #locals()[f"variable_{i}"] = i
    anotherService = True
    while(anotherService):
        print("")
        choices = serviceChoice()
        service = choices[0]
        pmtPID = choices[1]
        save_pmt_by_service_id(f"pmtXML{serviceCounter}.xml", service)
        
        #SCTE PID
        pid = getSCTEPID(f"pmtXML{serviceCounter}.xml")
        
        """
        hexPid = hex(pid)[2:].zfill(4)
        hexPid = '0x' + hexPid
        """
        #Replace SCTE with DSMCC element
        replaceSCTEElement(f"pmtXML{serviceCounter}.xml", pid)
        #save PMT packet as a variable
        pmtPacket = ""
        #pmtPacketHex = ""
        
        #print(pmtPID)
        #print(pid)
        
        
        #get the PMT PID from chosen service
        #locals()[f"pmtPID{serviceCounter}"] = int(pmtPID, 16)
        pmtPIDs.append(int(pmtPID, 16))
        
        #get SCTE PID
        #locals()[f"pid{serviceCounter}"] = int(pid, 16)
        sctePIDs.append(int(pid, 16))
        #change the PMT
        
        print("\nAnother Service?")
        print("0: No")
        print("1: Yes")
        anotherServiceChoice = int(input("Enter index of choice: "))
        if(anotherServiceChoice == 0):
            anotherService = False
        else:
            anotherService = True
            serviceCounter += 1
    
    print(f"\nPMT PIDs: {pmtPIDs}")
    print(f"SCTE PIDs: {sctePIDs}\n")
    
    #create an array of equal length to the pmtPIDs one, all false 
    pmtMadeArray = [False] * len(pmtPIDs)
    
    #create a PMT packet for all pmts
    for i in range (0, len(pmtMadeArray)):
        locals()[f"pmtPacket{serviceCounter}"] = ""
    
    
    
    
    
    #start a BUFFER of 7 for the packets
    buffer = []
    
    
    
    try:
        # Run the command and capture its output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, bufsize=0)

        # Define the packet size (188 bytes)
        packet_size = 188

        # Process the data in real-time
        #i = 0
        #variable for making the PMT packet
        pmtMade = False
        #start a continuity counter for each PID
        pmtContCounts = [0]*len(pmtPIDs)
        #start a continuity counter for each SCTE
        scteContCounts = [0]*len(pmtPIDs)
        
        
        while True:
            
            packet = process.stdout.read(packet_size)

            # Check if the subprocess has finished
            if not packet:
                break
            
            
            currentPid = struct.unpack('>H', packet[1:3])[0] & 0x1FFF
            #print(currentPid)
            #if PMT we need to convert
            
            #check if any of the PMT PIDs
            
            if(currentPid in pmtPIDs):
            
                #get the INDEX
                index = pmtPIDs.index(currentPid)
                
                #If a PMT has not been made, make one
                if(pmtMadeArray[index] == False):
                    
                    with open("singlePMT.ts", "wb") as file2:
                        file2.write(packet)
                    replace_table("singlePMT.ts", pmtPIDs[index], f"pmtXML{index}.xml", "singlePMT.ts")
                    pmtMadeArray[index] = True
                    #get the packet as a variable
                    with open("singlePMT.ts", "rb") as file2:
                        locals()[f"pmtPacket{index}"] = file2.read(188)
                        #pmtPacketHex = binascii.hexlify(pmtPacket).decode('utf-8')
                        #print(pmtPacket)
                        
                
                hex_string = binascii.hexlify(locals()[f"pmtPacket{index}"]).decode('utf-8')
                new_hex = hex(pmtContCounts[index] & 0xF)[2:]
                print(f"PMT inserted on PMT PID {currentPid} (PMT Continuity Counter {pmtContCounts[index] & 0xF})")
                

                # Replace the corresponding portion of the original hex string
                updated_string = hex_string[:7] + new_hex + hex_string[8:]
                
                #replace the CRC
                #print(updated_string)
                
                
                pmtPacketAlt = bytes.fromhex(updated_string)
                
          
               
                
                #update cont counts
                pmtContCounts[index] += 1
                pmtContCounts[index] &= 0x0F
                
                
                #want to send every 7 packets, buffer
                buffer.append(pmtPacketAlt)
                
             
                
                
                """
                if(len(buffer) == 7):
                
                    combined_buffer = b''.join(buffer)
                    udp_socket.sendto(combined_buffer, (ip2, port2))
                    #clear buffer
                    buffer = []
                """
                #print(binascii.hexlify(pmtPacketAlt).decode('utf-8'))
                #send packet to socket
                """
                udp_socket.sendto(pmtPacketAlt, (ip2, port2))
                """
                
                
            else:
                #cont counts
                index = sctePIDs.index(currentPid) if currentPid in sctePIDs else -1
                
                convPacket = convertSCTE(packet, nullChoice, function, sctePIDs, scteContCounts[index])
                #only increment null SCTE if replace null selected, if null packet is returned
                #check if null packet, only increment if NOT null packet
                if(currentPid in sctePIDs):
                    hex_string = binascii.hexlify(convPacket).decode('utf-8')
                    #print(hex_string)
                    if not(hex_string.startswith("471fff")):
                        if index != -1:
                            scteContCounts[index] += 1
                            scteContCounts[index] &= 0x0F
               
                    
                #if not null. i.e. ALWAYS SCTE, sometimes other packets, never PMT as dealt with before
                if(convPacket != bytearray()):
                    buffer.append(convPacket)
                    """
                    if(len(buffer) == 7):
                            
                        combined_buffer = b''.join(buffer)
                        udp_socket.sendto(combined_buffer, (ip2, port2))
                        #clear buffer
                        buffer = []
                    """
                    
                    
                    #send packet to socket
                    """
                    udp_socket.sendto(convPacket, (ip2, port2))
                    """
                    
            if(len(buffer) == 7):
                combined_buffer = b''.join(buffer)
                udp_socket.sendto(combined_buffer, (ip2, port2))
                #clear buffer
                buffer = []        
                    
    except Exception as e:
        print(f"Error: {e}")
        
        

    finally:
        # Ensure the subprocess is properly closed
        process.terminate()
        process.wait()

  
    
    
    #replace SCTE with DSMCC
    #replace PMT
    
    


    
if __name__ == "__main__":

    
    ip = argv[1]
    port = int(argv[2])
    ip2 = argv[3]
    port2 = int(argv[4])
    
    
    
    
    print(f"Live Converter Version: {applicationVersionNumber}\n")
    #Check for TS Duck
    if not(check_tsduck_version):
       print("TSDuck is required in the path for this application to work. \nDownload at https://tsduck.io/download/tsduck/") 
       sys.exit(0)
    else: 
        processStream(ip, port, ip2, port2)
     
    
    
    
    
   
