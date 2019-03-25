/******************************************************************************
*
* Copyright © 2018-2019 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
*
* This file is a part of the software package TinyTls, originally known as TinySsl.
* This software is written by Anthony Mai and is provided under the terms and
* conditions of the GNU General Public License Version 3.0 (GPL V3.0). For the
* specific GPL V3.0 license terms please refer to:
*         https://www.gnu.org/licenses/gpl.html.
*
* This Copyright Notices contained in this code. are NOT to be removed or modified.
* If this package is used in a product, Anthony Mai should be given attribution as
* the author of the parts of the library used. This can be in the form of a textual
* message at program startup or in documentation provided with the package.
*
* This library is free for commercial and non-commercial use as long as the
* following conditions are aheared to. The following conditions apply to
* all code found in this distribution:
*
* 1. Redistributions of source code must retain the copyright notice, this
*    list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*
*    "This product contains software written by Anthony Mai (Mai_Anthony@hotmail.com)
*     The original source code can obtained from such and such internet sites or by
*     contacting the author directly."
*
* 4. This software may or may not contain patented technology owned by a third party.
*    Obtaining a copy of this software, with or without explicit authorization from
*    the author, does NOT imply that applicable patents have been licensed. It is up
*    to you to make sure that utilization of this software package does not infringe
*    on any third party's patents or other intellectual proerty rights.
*
* THIS SOFTWARE IS PROVIDED BY ANTHONY MAI "AS IS". ANY EXPRESS OR IMPLIED WARRANTIES,
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
* The license and distribution terms for any publically available version or derivative
* of this code cannot be changed.  i.e. this code cannot simply be copied and put under
* another distribution license [including the GNU Public License.]
*
******************************************************************************/

/******************************************************************************
*
*  File Name:       dns.cpp
*
*  Description:     Implementation of domain name service look up IP resolution.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         10/20/2018 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>
#include <functional>
#if defined(_WIN32) | defined(_WIN64)
#include <winsock2.h>
#include <ipTypes.h>
typedef int socklen_t;
#else //defined(_WIN32) || defined(_WIN64)
#include<sys/socket.h>    //you know what this is for
#include<arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>    //getpid
#endif //defined(_WIN32) || defined(_WIN64)


//List of DNS Servers registered on the system
uint32_t gDnsIp = 0;
char dns_servers[10][100] = {"208.67.222.222"};
int dns_server_count = 0;
//Types of DNS resource records :)
 
#define T_A 1     //Ipv4 address
#define T_NS 2    //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6   // start of authority zone
#define T_PTR 12  // domain name pointer
#define T_MX 15   //Mail server

struct RES_RECORD;

//Function Prototypes
uint32_t ngethostbyname (const char* , int, std::function<bool(const RES_RECORD&)>);
int ToDnsName(unsigned char*, const char*);
int FromDnsName(unsigned char* dns);
const u_char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();
 
//DNS header structure
struct DNS_HEADER {
    uint16_t id; // identification number
 
    uint8_t rd :1; // recursion desired
    uint8_t tc :1; // truncated message
    uint8_t aa :1; // authoritive answer
    uint8_t opcode :4; // purpose of message
    uint8_t qr :1; // query/response flag
 
    uint8_t rcode :4; // response code
    uint8_t cd :1; // checking disabled
    uint8_t ad :1; // authenticated data
    uint8_t  z :1; // its z! reserved
    uint8_t ra :1; // recursion available
 
    uint16_t q_count; // number of question entries
    uint16_t ans_count; // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count; // number of resource entries
};
 
//Constant sized fields of query structure
struct QUESTION
{
    uint16_t qtype;
    uint16_t qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    const uint8_t* name;
    struct R_DATA* resource;
    union {
        const uint8_t* rdata;
        uint32_t    ip;
    };
};
 
//Structure of a Query
typedef struct
{
    uint8_t* name;
    struct QUESTION* ques;
} QUERY;

extern uint32_t getIp(const char* hostname);

uint32_t getIp(const char* hostname)
{
    //Get the DNS servers from the resolv.conf file
    get_dns_servers();

    uint32_t ip = 0;

    std::function<bool(const RES_RECORD&)> cb = [&ip](const RES_RECORD& r) -> bool {
        if (ntohs(r.resource->type) == 1) {
            ip = r.ip;
        }
        return true;
    };
     
    //Now get the ip of this hostname , A record
    ngethostbyname(hostname , T_A, cb);

    return ip;
}

static uint32_t getqid() {
    static uint32_t id = 1;
    return id++;
}

// Perform a DNS query by sending a UDP packet
uint32_t ngethostbyname(const char* host, int query_type, std::function<bool(const RES_RECORD&)> cb)
{
    unsigned char buf[65536],*qname,*reader;
    int i, stop, s, len, qlen, rlen = 0;
    uint32_t ip = 0;
 
    struct RES_RECORD answer,auth,addit; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;
 
    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries
 
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = htonl(gDnsIp); // inet_addr(dns_servers[0]); //dns servers
 
    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;
 
    dns->id = (uint16_t) htons(getqid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
 
    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    qlen = ToDnsName(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + qlen]; //fill it
 
    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
    len = sizeof(struct DNS_HEADER) + qlen + sizeof(struct QUESTION);
    if( sendto(s,(char*)buf, len, 0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        return 0;
    }
     
    //Receive the answer
    i = sizeof(dest);
    if( (rlen = recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i )) < 0)
    {
        return 0;
    }
 
    dns = (struct DNS_HEADER*) buf;
 
    //move ahead of the dns header and the query field
    reader = &(buf[len]);
 
    //Start reading answers
    stop=0;
 
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answer.name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answer.resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);

        if(ntohs(answer.resource->type) == 1) //if its an ipv4 address
        {
            answer.ip = (uint32_t(reader[0])<<24) | (uint32_t(reader[1])<<16) | (uint32_t(reader[2])<<8) | uint32_t(reader[3]);
            reader = reader + ntohs(answer.resource->data_len);
            if (ip == 0) ip = answer.ip;
        }
        else
        {
            answer.rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }

        if (cb) cb(answer);
    }

    return ip;
#if WANT_EXTRA_STUFF
    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }
 
    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;
 
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].ip = (uint32_t(reader[0]) << 24) | (uint32_t(reader[1]) << 16) | (uint32_t(reader[2]) << 8) | uint32_t(reader[3]);
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }

    return ip;
#endif //WANT_EXTRA_STUFF
}
 
const u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    //read the names in 3www6google3com format
    if (*reader >= 192) {
        int offset = (((*reader)&0x003F) << 8) + reader[1]; //49152 = 11000000 00000000 ;)
        FromDnsName(buffer + offset);
        *count = 2;
        return (buffer + offset+1);
    } else {
        *count = FromDnsName(reader);
        return reader + 1;
    }
}

// Get the DNS servers from /etc/resolv.conf file on Linux
void get_dns_servers()
{
    if (gDnsIp) return;

#if defined(WIN32) || defined(WIN64)
    {
        HMODULE hDll = LoadLibraryA("iphlpapi.dll");
        if (hDll) {
            union {
                FIXED_INFO fi;
                uint8_t    buff[1024];
            } u;
            ULONG slen = sizeof(u);
            int err = 0;
            DWORD (WINAPI *GetNetParams) (PFIXED_INFO, PULONG) = (DWORD (WINAPI *)(PFIXED_INFO, PULONG))GetProcAddress(hDll, "GetNetworkParams");
            if (GetNetParams && NOERROR == (err = GetNetParams(&u.fi, &slen))) {
                gDnsIp = ntohl(inet_addr(u.fi.DnsServerList.IpAddress.String));
                for (int i = 0; (dns_servers[0][i] = u.fi.DnsServerList.IpAddress.String[i]); i++);
            } else {
                ERROR_INVALID_PARAMETER;
                err = err;
            }
            FreeLibrary(hDll);
        }
    }
#else //if defined(LINUX) || defined(_LINUX)
    FILE *fp;
    char line[200] , *p;

    if ((fp = fopen("/etc/resolv.conf" , "r"))) {
        while(fgets(line , 200 , fp)) {
            if(line[0] == '#') continue;
            if (*((const uint32_t*)line) == *((const uint32_t*)"nameserver")) {
                p = line + 11;
                gDnsIp = ntohl(inet_addr(p));
                if (gDnsIp) break; // Happy with first one we got.
            }
        }
        fclose(fp);
    }
#endif //defined(WIN32) || defined(WIN64)
}
 
// This converts www.google.com to 3www6google3com format
int ToDnsName(unsigned char* dns, const char* host) 
{
    int i = 0, j = 0;

    *dns++ = '.';
    do if( (*dns++ = host[i]), (host[i] =='.' || host[i] == 0x00)) {
        dns[j - i - 2] = i - j; j = i+1;
    } while (host[i++]);
    return i+1;
}

// This converts www.google.com to 3www6google3com format
int FromDnsName(unsigned char* dns)
{
    int i = 0, j = 0;
    while ((j = dns[i]) != '.') {
        if (j == 0) break;
        dns[i] = '.'; i += j + 1;
    }
    while (dns[i++]);
    return i;
}
