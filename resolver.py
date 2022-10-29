from os import abort
from pickle import NONE
import sys
import time
import socket
from datetime import datetime
import dns
import dns.message as dns_message
import dns.query as dns_query
import dns.name as dns_name
import dns.rdatatype, dns.opcode, dns.rcode, dns.flags


#These are root servers' ip address extracted from https://www.iana.org/domains/root/servers to query
root_server_ip_addresses =  ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]
#public DNS addresses
#root_server_ip_addresses =  ["8.8.8.8"]
#local DNS Altice
#root_server_ip_addresses =  ["192.168.1.1"]

#This function sends a single query to get the IP address of Top Level Domain IPs
def recursive_resolve_over_udp(domain_name, record_type, name_server):
    domain_name = dns_name.from_text(domain_name)
    query = dns_message.make_query(qname = domain_name, rdtype = record_type)
    dns_rsp = dns_query.udp(q = query, where = name_server, timeout = 10)
    return dns_rsp

#This function form the custom output. we need to strip some values to form the customized output mentioned by the assignment description.
def make_output(domain_name, dns_rsp, elapsed_time):   
    
    output_string = 'QUESTION SECTION:\n'
    for ans_qs in dns_rsp.question:
        output_string += ans_qs.to_text()
        output_string += "\n"

    output_string += "\n"    

    num_answers = 0
    for ans in dns_rsp.answer:
        num_answers += len(ans.items)
    if num_answers > 0: 
        output_string += 'ANSWER SECTION:\n'
        for ans in dns_rsp.answer:
            ans_parts = ans.to_text().split('\n')
            for ans_parts_cur in ans_parts:
                ans_parts_parts = ans_parts_cur.split(' ')
                output_string += ans_parts_parts[0]
                output_string += "\t"
                output_string += ans_parts_parts[2]
                output_string += "\t"
                output_string += ans_parts_parts[3]
                output_string += "\t"
                output_string += ans_parts_parts[4]
                output_string += "\n"
        output_string += "\n"
    
    num_authority = 0
    for ans in dns_rsp.authority:
        num_authority += len(ans.items)
    if num_authority > 0:
        output_string += 'AUTHORITY SECTION:\n'
        for ans in dns_rsp.authority:
            ans_parts = ans.to_text().split('\n')
            for ans_parts_cur in ans_parts:
                ans_parts_parts = ans_parts_cur.split(' ')
                output_string += ans_parts_parts[0]
                output_string += "\t"
                output_string += ans_parts_parts[2]
                output_string += "\t"
                output_string += ans_parts_parts[3]
                output_string += "\t"
                output_string += ans_parts_parts[4]
                output_string += "\n"
        output_string += "\n"

    
    output_string += "Query time: {} msec\n".format(str(int(elapsed_time * 1000)))
    output_string += "WHEN: {}\n".format(datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
    output_string += "MSG SIZE  rcvd: {}\n".format(sys.getsizeof(dns_rsp.to_text()))
    
    return output_string

#this function is responsible for doing core functionality of a resolver.
def resolver(domain_name, record_type, cname = False, ret_ip = False):   
    for root_server_ip_address in root_server_ip_addresses:
        try:
            dns_rsp = recursive_resolve_over_udp(domain_name, record_type, name_server = root_server_ip_address)
        except Exception as err:
            continue
        ##it reads additional section of a dns response to extract all IP addresses of next name servers in the path of resolve    
        while(not dns_rsp.answer):
            if len(dns_rsp.additional) > 0:
                for answer_rrs in dns_rsp.additional:
                    if answer_rrs[0].rdtype == dns.rdatatype.A:
                        next_ns_addr = answer_rrs[0].address
                        # send a query to TLD servers to find an IP address
                        try:
                            next_ns_rsp = recursive_resolve_over_udp(domain_name, record_type, name_server = next_ns_addr)
                            if cname and next_ns_rsp.answer and next_ns_rsp.answer[0].rdtype == dns.rdatatype.CNAME:
                                return next_ns_rsp
                            elif ret_ip and next_ns_rsp.answer and next_ns_rsp.answer[0].rdtype == dns.rdatatype.A:
                                return next_ns_rsp
                            dns_rsp = next_ns_rsp
                            break
                        except Exception as err:
                            pass
            #check the Authority section when Additional section is empty.
            #information regarding authoritative name servers is in the authority section and we want to verify and resolve domain name of an authoritative name server.             
            elif len(dns_rsp.authority) > 0:
                for answer_rrs in dns_rsp.authority:
                    if answer_rrs.rdtype == dns.rdatatype.SOA:
                        return dns_rsp
                    
                    ns_dname = answer_rrs[0].target.to_text()
                    next_ns_rsp = resolver(ns_dname, 'A', ret_ip = True)

                    if not cname:
                        for auth_rrset in next_ns_rsp.answer:
                            auth_ip_addr = auth_rrset[0].address
                            try:
                                auth_dns_rsp = recursive_resolve_over_udp(domain_name, record_type, name_server = auth_ip_addr)
                                dns_rsp = auth_dns_rsp
                            except Exception as err:
                                pass
                    else:
                        return next_ns_rsp
                        
        #in the response if we find A or SOA record, we return the IP as the result of resolution
        for answer_rrs in dns_rsp.answer:
            if dns.rdatatype.from_text(record_type).value == dns.rdatatype.A and (answer_rrs.rdtype == dns.rdatatype.SOA or answer_rrs.rdtype == dns.rdatatype.A):
                return dns_rsp
        #extract CNAME from Answer section to resolve the corresponding IP address
        for answer_rrs in dns_rsp.answer:
            while answer_rrs.rdtype == dns.rdatatype.CNAME:
                cname_domain_name = answer_rrs[0].target.to_text()
                cname_dns_rsp = resolver(cname_domain_name, 'A', cname = True)
                for cname_rrs in cname_dns_rsp.answer:
                    if cname_rrs.rdtype == dns.rdatatype.CNAME:
                        dns_rsp.answer.append(cname_rrs)
                        break
                    else:
                        auth_ip = cname_rrs[0].address
                        try:
                            auth_dns_rsp = recursive_resolve_over_udp(cname_domain_name, record_type, name_server = auth_ip)
                            if not auth_dns_rsp.answer and auth_dns_rsp.authority: 
                                if dns.rdatatype.from_text(record_type).value != dns.rdatatype.A:
                                    dns_rsp.authority.extend(auth_dns_rsp.authority)
                                else:
                                    for auth_rrs in auth_dns_rsp.authority:
                                        auth_domain_name = auth_rrs.name.to_text()
                                        auth_dns_rsp = resolver(auth_domain_name, 'A', cname = True)
                                        if auth_dns_rsp.answer:
                                            break
                            for auth_rrs in auth_dns_rsp.answer:
                                dns_rsp.answer.append(auth_rrs)
                            break
                        except Exception as err:
                            pass
                break
        break
    return dns_rsp               

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: mydig domain_name RR")
        print("This program needs 2 arguments, Domain Name, and RR. RR must be one of A, NS or MX value")
        exit(0)
    

    domain_name = sys.argv[1]
    record_type = sys.argv[2]

    if record_type not in ['A', 'NS', 'MX']:
        print("RR type must be one of A, NS or MX value")
        sys.exit(1)
    
    start_time = time.time()
    dns_rsp = resolver(domain_name, record_type)
    elapsed_time = time.time() - start_time

    output= make_output(domain_name, dns_rsp, elapsed_time)
    print(output)
    
    
#ref:
#https://stackoverflow.com/questions/4066614/how-can-i-find-the-authoritative-dns-server-for-a-domain-using-dnspython/4066624
#https://stackoverflow.com/questions/54778160/python-requests-library-not-resolving-non-authoritative-dns-lookups
#https://stackoverflow.com/questions/13842116/how-do-we-get-txt-cname-and-soa-records-from-dnspython
#https://stackoverflow.com/questions/18898847/dnspython-raises-noanswer-in-spite-of-query-answer