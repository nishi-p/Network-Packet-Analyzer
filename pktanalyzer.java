import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * pktanalyzer.java
 *
 * Version :    1.1
 *
 * This program reads a set of network packets and produces a detailed summary of those packets. It can extract and
 * display the different headers of the captured packets in the binary file. It is capable of analyzing UDP, TCP, ICMP
 * and ARP packets.
 *
 * Usage: java pktanalyzer <packet-name>
 * Eg: java pktanalyzer arprequest.bin
 *
 * @author Nishi Parameshwara
 *
 **/

public class pktanalyzer {

    /**
     * The main function
     * @param args  Command line arguments (ignored)
     * @throws IOException If reading/writing/searching operation fails
     */
    public static void main(String[] args) throws IOException {
        String bin_file = readfile(args);
        //Reads binary file as bytes
        byte[] fileContents =  Files.readAllBytes(Paths.get(bin_file));
        System.out.println("Packet size: " + fileContents.length + " bytes");
        //Set size for Ethernet Header
        byte[] ethernet = new byte[14];
        //Set size for IP Frame i.e. Header (20 bytes) + Data
        byte[] ip = new byte[fileContents.length - 14];

        //ethernet header
        System.arraycopy(fileContents, 0, ethernet, 0, 14);
        ethernet_head(ethernet);

        //ip header (20 bytes) + data
        System.arraycopy(fileContents, 14, ip, 0, fileContents.length - 14);
        ip_head(ip);
    }

    /**
     * Function to return filename from command line.
     * @return path of the file/or filename
     */
    static String readfile(String[] args) {
        String filepath = "";

        if (args.length == 0) {
            System.out.println("Enter Filepath of packet: ");
            Scanner scan = new Scanner(System.in);
            filepath = scan.next();
            scan.close();
        } else if (args.length == 1) {
            filepath = args[0];
        } else {
            System.out.println("Usage: java pktanalyzer filepath");
            System.exit(1);
        }
        return filepath;
    }

    /**
     * Function to decode the Ethernet Header from network packet provided by user.
     * @param argument1 Byte Array containing Ethernet Header
     */
     public static void ethernet_head(byte[] argument1) {
         System.out.println("--------------------------------------------------Ethernet Header-----" +
                 "---------------------------------------------");
         System.out.print("Destination MAC Address: ");
         for (int i = 0; i < 6; i++) {
             //Single Byte Integer value conversion to 2-character Hexadecimal
             String st = String.format("%02X", argument1[i]);
             if (i == 5) {
                 System.out.print(st);
             } else {
                 System.out.print(st + ":");
             }
         }

         System.out.print("\n");
         System.out.print("Source MAC Address: ");
         for (int i = 6; i < 12; i++) {
             //Single Byte Integer value conversion to 2-character Hexadecimal
             String st = String.format("%02X", argument1[i]);
             if (i == 11) {
                 System.out.print(st);
             } else {
                 System.out.print(st + ":");
             }
         }

         System.out.print("\n");
         System.out.print("Ethernet Frame Type: ");
         for (int i = 12; i < 14; i++) {
             //Single Byte Integer value conversion to 2-character Hexadecimal
             String st = String.format("%02X", argument1[i]);
             System.out.print(st);
         }
         System.out.print(" (IP)");
         System.out.print("\n");
     }

    /**
     * Function to decode the IP Header from network packet provided by user.
     * @param argument2 Byte Array containing IP Frame i.e. Header + Data
     */
     public static void ip_head(byte[] argument2){
         byte[] header = new byte[argument2.length];

         //integer conversion to convert signed bytes to unsigned bytes.
         int[] argument3 = new int[argument2.length];
         //Converting signed bytes to unsigned bytes in an integer with the help of a mask. 2's complement is not required
         //as Java already uses two’s complement to represent signed numbers (positive and negative). Java does not have
         //unsigned bytes, so convert the bytes to unsigned bytes in an integer to represent 8 bits within 0-255 and not
         //-128 to 127. Integer values needs to be displayed.
         //https://www.therevisionist.org/software-engineering/java/terms/signed-vs-unsigned/
         for(int i=0; i<argument2.length; i++) {
             //2's complement code
             //if(argument2[i]<0){
                 //System.out.println(argument2[i]);
                 //argument3[i] = ((argument2[i])^0xff+0x01)&0xff;
             //}
             //else{

             //bytes to unsigned bytes in an integer by casting the byte into an int and mask (bitwise and) the new int
             //with a 0xff to get the last 8 bits or prevent sign extension (get only positive number representation).
             //https://mkyong.com/java/java-convert-bytes-to-unsigned-bytes/
             //https://mkyong.com/java/java-sign-extension/
             argument3[i] = argument2[i]&0xff; //32 bit representation & 0000 0000 0000 0000 0000 0000 1111 1111
         }
         /*To isolate any set of bits, apply an AND mask. If you want the last X bits of a value,
         unsigned  mask;
         mask = (1 << X) - 1;
         lastXbits = value & mask;

         If you want to isolate a run of X bits in the middle of 'value' starting at 'startBit',
         unsigned  mask;
         mask = ((1 << X) - 1) << startBit;
         isolatedXbits = value & mask;

         Not applicable for X=32 (int) or X=64 (long)
         */
         System.out.println("-----------------------------------------------------IP Header--" +
                 "---------------------------------------------------");
         //Extracting first 4 bits from integer
         System.out.println("IP Version: " + (argument3[0]>>4));
         //Extracting last 4 bits from integer
         System.out.println("IP Header Length: " + (argument3[0]&(1<<4)-1) + "*32 = " + ((argument3[0]&(1<<4)-1)*32) +
                 " bits/8 = " + (((argument3[0]&(1<<4)-1)*32)/8) + " bytes"); //5*32 = 160/8 bits = 20 bytes
         //Single Byte Integer value conversion to 2-character Hexadecimal
         System.out.println("Types of Service: 0x" + (String.format("%02X", argument3[1])));
         //Extracting first 6 bits
         System.out.println("DSCP: "+ (argument3[0]>>2));
         //Extracting last 2 bits
         System.out.println("ECN: "+ (argument3[0]&(1<<2)-1));
         //Extracting first 3 bits --> 8-3 = 5
         int val1 = (argument3[1]>>5);
         switch(val1) {
             case 0:
                 System.out.println("000----- = Routine IP Precedence");
                 break;
                 case 1:
                     System.out.println("001----- = Priority IP Precedence");
                     break;
                 case 2:
                     System.out.println("010----- = Immediate IP Precedence");
                     break;
                 case 3:
                     System.out.println("011----- = Flash IP Precedence");
                     break;
                 case 4:
                     System.out.println("100----- = Flash Override IP Precedence");
                     break;
                 case 5:
                     System.out.println("101----- = Critic/ECP IP Precedence");
                     break;
                 case 6:
                     System.out.println("110----- = Internetwork Control IP Precedence");
                     break;
                 case 7:
                     System.out.println("111----- = Network Control IP Precedence");
                     break;
                 default:
                     break;
         }

         //Extracting first 4 bits and the last bit of the result
         if ((argument3[1]>>4&(1<<1)-1) == 0){
             System.out.println("---0---- = Normal Delay");
         }
         else{
             System.out.println("---1---- = Low Delay");
         }

         //Extracting first 5 bits and the last bit of the result
         if ((argument3[1]>>3&(1<<1)-1) == 0){
             System.out.println("----0--- = Normal Throughput");
         }
         else{
             System.out.println("----1--- = High Throughput");
         }

         //Extracting first 6 bits and the last bit of the result
         if ((argument3[1]>>2&(1<<1)-1) == 0){
             System.out.println("-----0-- = Normal Reliability");
         }
         else{
             System.out.println("-----1-- = High Reliability");
         }

         /*Shift left and or-ing is equivalent to multiplication by power of two and adding.
         For combination x number of higher bits and lower bits, Higher bits << x | lower bits*/
         //Combining two bytes from byte[]
         System.out.println("Total length: " + (argument3[2]<<8|argument3[3]) + " bytes");
         //Combining two bytes from byte[]
         System.out.println("Identification: " + (argument3[4]<<8|argument3[5]));
         //Extracting first 3 bits
         System.out.println("Flags: 0x" + (String.format("%02X", argument3[6]>>5)));
         //Extracting first 2 bits and the last bit of the result
         if ((argument3[6]>>6&(1<<1)-1) == 0){
             System.out.println("-0- = Do not Fragment (DF) bit is 0. The packet should be fragmented");
         }
         else{
             System.out.println("-1- = Do not Fragment (DF) bit is 1. The packet should not be fragmented");
         }

         //Extracting first 3 bits and the last bit of the result
         if ((argument3[6]>>5&(1<<1)-1) == 0){
             System.out.println("--0 = More Fragments (MF) bit is 0. This is last fragment.");
         }
         else{
             System.out.println("--1 = More Fragments (MF) bit is 1. More Fragments are coming");
         }

         //Combining last five bits of one byte from byte[] with another byte from byte[]
         //Extract last five bits from a byte = 000xxxxx & 00011111 = xxxxxx == 000xxxxx & ((1<<5)-1)
         System.out.println("Fragment offset: " + (((argument3[6]&31)<<8)|argument3[7]) + " bytes");
         System.out.println("Time to live: " + argument3[8] + " seconds/hops");
         System.out.println("Protocol: " + argument3[9]);
         //Combining two bytes from byte[]
         System.out.println("Header checksum: 0x" + (String.format("%02X", (argument3[10]<<8)| argument3[11])));
         System.out.println("Source IP address: " + argument3[12] + "." + argument3[13] + "." + argument3[14] + "." +
                 argument3[15]);
         System.out.println("Destination IP address: " + argument3[16] + "." + argument3[17] + "." + argument3[18] + "."
                 + argument3[19]);
         //Extracted 20 bytes of IP header information

         //Check if Options for IP header exists by checking the condition IHL > 5
         /*The IPv4 header is variable in size due to the optional 14th field (options). The Internet Header Length (IHL)
         field contains the size of the IPv4 header, it has 4 bits that specify the number of 32-bit words in the header.
         The minimum value for this field is 5, which indicates a length of 5 × 32 bits = 160 bits = 20 bytes. As a
         4-bit field, the maximum value is 15, this means that the maximum size of the IPv4 header is 15 × 32 bits =
         480 bits = 60 bytes.*/

         //Check if IHL > 5 i.e. extract last 4 bits
         if ((argument3[0]&(1<<4)-1) > 5) {
             int length_val = ((argument3[0]&(1<<4)-1)*32)/8;
             int option_length = length_val - 20;
             //Copy the payload of IP header, skipping the options field for further analysis
             System.arraycopy(argument2, 20 + option_length, header, 0, argument2.length - length_val);
             System.out.println("IP Header has Options of length " + option_length + " bytes");
         } else {
             //Copy the payload of IP header. Options field is not present.
             System.arraycopy(argument2, 20, header, 0, argument2.length - 20);
             System.out.println("IP Header has No options");
         }

         //Check the type of header that IP header payload contains by checking the field Protocol
         if (argument2[9] == 17){
             udp_head(header);
         }
         else if (argument2[9] == 6){
             tcp_head(header);
         }
         else if (argument2[9] == 1){
             icmp_head(header);
         }
         else{ //54
             arp_head(argument2);
         }
    }

    /**
     * Function to decode the UDP Header from the UDP packet provided by user.
     * @param argument4 Byte Array containing encapsulated UDP Header
     */
    public static void udp_head(byte[] argument4){
        int counter = 0;
        int[] argument5 = new int[argument4.length];
        //Converting signed bytes to unsigned bytes by 2's complement
        for(int i=0; i<argument4.length; i++) {
            argument5[i] = argument4[i]&0xff;
        }

        System.out.println("---------------------------------------------------UDP Header---" +
                "---------------------------------------------------");
        //Combining two bytes from byte[]
        System.out.println("Source port: " + ((argument5[0]<<8)|argument5[1]));
        //Combining two bytes from byte[]
        System.out.println("Destination port: " + ((argument5[2]<<8)|argument5[3]));
        //Combining two bytes from byte[]
        System.out.println("Length: " + ((argument5[4]<<8)|argument5[5]));
        //Combining two bytes from byte[]
        System.out.println("UDP Checksum: 0x" + (String.format("%02X", (argument5[6]<<8)| argument5[7])));
        //UDP header length is 8. Check for the length of data field in UDP packet
        byte[] data = new byte[argument5.length - 8];
        //Integer values are not needed, so no need to convert signed to unsigned.
        System.arraycopy(argument4, 8, data, 0, data.length);
        System.out.println("UDP Payload/Data:\n ");
        System.out.println("Hexadecimal Values= ");
        for (int i = 8; i<argument5.length; i++) {
            counter++;
            System.out.print(String.format("%02X", (argument5[i])) + " ");
            //Print 8 values in a row
            if (counter%8 == 0){
                System.out.print("\n");
            }
        }
        System.out.println("\n");
        //Convert byte[] into string data
        System.out.println("ASCII Values=\n" + new String(data));
    }

    /**
     * Function to decode the TCP Header from the TCP packet provided by user.
     * @param argument6 Byte Array containing encapsulated TCP Header
     */
    public static void tcp_head(byte[] argument6){
        int counter = 0;
        byte[] header1 = new byte[argument6.length];

        long[] argument7 = new long[argument6.length];
        //Converting signed bytes to unsigned bytes by 2's complement
        for(int i=0; i<argument6.length; i++) {
            argument7[i] = argument6[i]&0xff;
        }

        System.out.println("---------------------------------------------------TCP Header-----" +
                "-------------------------------------------------");
        //Combining two bytes from byte[]
        System.out.println("Source port: " + ((argument7[0]<<8)|argument7[1]));
        //Combining two bytes from byte[]
        System.out.println("Destination port: " + ((argument7[2]<<8)|argument7[3]));
        //Combining four bytes from byte[]
        System.out.println("Sequence Number: " + ((argument7[4]<<24)|(argument7[5]<<16)| (argument7[6]<<8)|argument7[7]));
        //Combining four bytes from byte[]
        System.out.println("Acknowledgement Number: " + (((argument7[8]<<24)| (argument7[9]<<16)|(argument7[10]<<8)|
                argument7[11])));
        //Extracting first four bits --> Header Length
        System.out.println("Data Offset: " + (argument7[12]>>4&(1<<4)-1) + "*32 = 256 bits/8 = 32 bytes");
        //Combining last six bits of one byte from byte[]
        System.out.println("Flags: 0x" + (String.format("%02X", ((argument7[13]&((1<<6)-1))))));
        //Extracting first 3 bits and the last bit of the result
        if ((argument7[13]>>5&(1<<1)-1) == 0){
            System.out.println("--0----- = No Urgent Pointer");
        }
        else{
            System.out.println("--1----- = Urgent Pointer");
        }
        //Extracting first 4 bits and the last bit of the result
        if ((argument7[13]>>4&(1<<1)-1) == 0){
            System.out.println("---0---- = No Acknowledgement");
        }
        else{
            System.out.println("---1---- = Acknowledgement");
        }
        //Extracting first 5 bits and the last bit of the result
        if ((argument7[13]>>3&(1<<1)-1) == 0){
            System.out.println("----0--- = No Push Request");
        }
        else{
            System.out.println("----1--- = Push Request");
        }
        //Extracting first 6 bits and the last bit of the result
        if ((argument7[13]>>2&(1<<1)-1) == 0){
            System.out.println("-----0-- = No Reset");
        }
        else{
            System.out.println("-----1-- = Reset");
        }
        //Extracting first 7 bits and the last bit of the result
        if ((argument7[13]>>1&(1<<1)-1) == 0){
            System.out.println("------0- = No Syn");
        }
        else{
            System.out.println("------1- = Syn");
        }
        //Extracting first 8 bits and the last bit of the result
        if ((argument7[13]&(1<<1)-1) == 0){
            System.out.println("-------0 = No Fin");
        }
        else{
            System.out.println("-------1 = Fin");
        }
        //Combining two bytes from byte[]
        System.out.println("Window: " + ((argument7[14]<<8)|argument7[15]));
        //Combining two bytes from byte[]
        System.out.println("TCP Checksum: 0x" + (String.format("%02X", (argument7[16]<<8)|
                (argument7[17]))));
        //Combining two bytes from byte[]
        System.out.println("Urgent Pointer: " + ((argument7[18]<<8)|argument7[19]));
        //Check if Options for UDP header exists by checking the condition Header Length > 5

        /*This field specifies the length in bytes of the UDP header and UDP data. The minimum length is 8 bytes, the
        length of the header. The field size sets a theoretical limit of 65,535 bytes (8 byte header + 65,527 bytes of
        data) for a UDP datagram.*/
        if (argument7[12]>>4 >5) {
            int length_val = (int) ((argument7[12]>>4)*32)/8;
            int option_length = length_val - 20;
            //Copy the payload of UDP header, skipping the options field for further analysis
            System.arraycopy(argument6, 20 + option_length, header1, 0, argument7.length - length_val);
            System.out.println("TCP Header has Options of length " + option_length + " bytes");
        } else {
            //Copy the payload of UDP header. Options field is not present.
            System.arraycopy(argument6, 20, header1, 0, argument7.length - 20);
            System.out.println("TCP Header has No options");
        }

        System.out.println("TCP Payload/Data:\n ");
        System.out.println("Hexadecimal Values= ");
        for (int i = 0; i<argument7.length; i++) {
            counter++;
            System.out.print(String.format("%02X", (header1[i])) + " ");
            //Print 8 values in a row
            if (counter%8 == 0){
                System.out.print("\n");
            }
        }
        System.out.println("\n");
        //Convert byte[] into string data
        System.out.println("ASCII Values=\n" + new String(header1));
    }

    /**
     * Function to decode the ICMP Header from the ICMP packet provided by user.
     * @param argument8 Byte Array containing encapsulated ICMP Header
     */
    public static void icmp_head(byte[] argument8){
        long[] argument9 = new long[argument8.length];
        //Converting signed bytes to unsigned bytes by 2's complement
        for(int i=0; i<argument8.length; i++) {
            argument9[i] = argument8[i]& 0xff;
        }
        System.out.println("---------------------------------------------------ICMP Header--" +
                "----------------------------------------------------");
        System.out.println("Message Type: " + (argument9[0]));
        System.out.println("Code: " + (argument9[1]));
        //Combining two bytes from byte[]
        System.out.println("ICMP Checksum: 0x" + (String.format("%02x", (argument9[2]<<8)|(argument9[3]))));
    }

    /**
     * Function to decode the ARP Header from the ARP packet provided by user.
     * @param argument10 Byte Array containing encapsulated ARP Header
     */
    public static void arp_head(byte[] argument10){
        long[] argument11 = new long[argument10.length];
        //Converting signed bytes to unsigned bytes
        for(int i=0; i<argument10.length; i++) {
            argument11[i] = argument10[i]& 0xff;
        }
        System.out.println("---------------------------------------------------ARP Header---" +
                "---------------------------------------------------");
        //Check Opcode
        System.out.println("From Opcode");
        if (((argument11[6]<<8)|argument11[7]) == 1) {
            System.out.println("This is an ARP Request");
        }
        else{
            System.out.println("This is an ARP Response");
        }
        //Combining two bytes from byte[]
        System.out.println("Hardware Type: " + ((argument11[0]<<8)|argument11[1]));
        //Combining two bytes from byte[]
        System.out.print("Protocol Type: 0x" + (String.format("%02x", (argument11[2]<<8)|argument11[3])));
        //Check for protocol type
        if (((argument11[2]<<8)|argument11[3]) == 2048){
            System.out.println(" (IPv4)");
        }
        //Combining two bytes from byte[]
        System.out.println("Hardware Address Length: " + (argument11[4]));
        System.out.println("Protocol Address Length: " + (argument11[5]));
        //Combining two bytes from byte[]
        System.out.print("Operation Request Code: " + ((argument11[6]<<8)|argument11[7]));
        if (((argument11[6]<<8)|argument11[7]) == 1) {
            System.out.println(" (ARP Request)");
        }
        else{
            System.out.println(" (ARP Response)");
        }
        //Combining six bytes from byte[]
        System.out.print("Source Hardware Address: ");
        for (int i = 8; i < 14; i++) {
            //Bytes conversion to Hexadecimal
            String st = String.format("%02X", argument11[i]);
            if (i == 13) {
                System.out.println(st);
            } else {
                System.out.print(st + ":");
            }
        }
        /***************************************************************************************
         * Sample Code Availability: http://helpdesk.objects.com.au/java/how-do-i-convert-an-ip-
         * address-into-an-array-of-bytes
         ***************************************************************************************/
        //Combining four bytes from byte[]
        System.out.print("Source Protocol Address: ");
        String addressStr = "";
        for (int i = 14; i < 18; ++i)
        {
            long t = 0xFF & argument11[i]; //Convert signed bytes to unsigned bytes
            addressStr += "." + t;
        }
        addressStr = addressStr.substring(1); //Extract substring from the first position, excluding the 0th position.
        System.out.println(addressStr);
        //Combining six bytes from byte[]
        System.out.print("Target Hardware Address: ");
        for (int i = 18; i < 24; i++) {
            //Bytes conversion to Hexadecimal
            String st = String.format("%02X", argument11[i]);
            if (i == 23) {
                System.out.println(st);
            } else {
                System.out.print(st + ":");
            }
        }
        /***************************************************************************************
         * Sample Code Availability: http://helpdesk.objects.com.au/java/how-do-i-convert-an-ip-
         * address-into-an-array-of-bytes
         ***************************************************************************************/
        //Combining four bytes from byte[]
        System.out.print("Target Protocol Address: ");
        StringBuilder addressStr1 = new StringBuilder();
        //Combining four bytes
        for (int i = 24; i < 28; ++i)
        {
            long t = 0xFF & argument11[i]; //Convert signed bytes to unsigned bytes
            addressStr1.append(".").append(t);
        }
        addressStr1 = new StringBuilder(addressStr1.substring(1)); //Extract substring from the first position,
        //excluding the 0th position.
        System.out.println(addressStr1);
    }
} //pktanalyzer