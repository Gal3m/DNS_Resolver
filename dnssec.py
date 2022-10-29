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
import dns.rdatatype, dns.opcode, dns.rcode, dns.flags, dns.dnssec


#These are root servers' ip address extracted from https://www.iana.org/domains/root/servers to query
root_server_ip_addresses =  ["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230.10",
"192.5.5.241","192.112.36.4","198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42",
"202.12.27.33"]
 
 # In this http://data.iana.org/root-anchors/root-anchors.xml address we can find active root anchor 
root_anchor = '20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D'.lower()
hash_functions = {1: 'SHA1', 2: 'SHA256'}


def recursive_resolve_over_udp(domain_name, record_type, name_server, use_dnssec):
    domain_name = dns_name.from_text(domain_name)
    query = dns_message.make_query(qname = domain_name, rdtype = record_type, want_dnssec = use_dnssec)
    dns_rsp = dns_query.udp(q = query, where = name_server, timeout = 5)
    return dns_rsp

def check_dnssec(dns_rsp, dnskey_rsp, parent_ds_rrset, with_record):
    # Extract DNSKey RRSet(PubKSK + PubZSK for the zone) and its RRSig
    dnskey_rrsig = next((rrset for rrset in dnskey_rsp.answer if rrset.rdtype == dns.rdatatype.RRSIG), None)
    dnskey_rrset, ksk = extract_crypto_form_answer(dnskey_rsp.answer)
    if with_record:
        #Extract A RRSet from Answer section of DNSSec response of Authoritative NS
        zone_rrset = next((rrset for rrset in dns_rsp.answer if rrset.rdtype == dns.rdatatype.A), None)
        #Return the record having RRSig rdatatype from either the Answer or Authority Section of the DNSSec response
        zone_rrsig = next((rrset for rrset in dns_rsp.answer if rrset.rdtype == dns.rdatatype.RRSIG), None)
    else:
        #Extract DS RRSet from Answer section of DNSSec response of non-Authoritative NS
        zone_rrset = next((rrset for rrset in dns_rsp.authority if rrset.rdtype == dns.rdatatype.DS), None)
        #Return the record having RRSig rdatatype from either the Answer or Authority Section of the DNSSec response
        zone_rrsig = next((rrset for rrset in dns_rsp.authority if rrset.rdtype == dns.rdatatype.RRSIG), None)
    if zone_rrset == None:     
        print(parent_ds_rrset.name.to_text()+" does not support DNSSEC")
        return False, zone_rrset  
    #DNSSec has been successfully implemented if all required condition are met.
    validate_dnssec = check_zone(parent_ds_rrset, ksk) and check_dnskey_rrset(dnskey_rrset, dnskey_rrsig) and check_ds_rrset(zone_rrset, zone_rrsig, dnskey_rrset)
    return validate_dnssec, zone_rrset


def check_dnskey_rrset(dnskey_rrset, dnskey_rrsig):
    try:
        dns.dnssec.validate(rrset = dnskey_rrset, rrsigset = dnskey_rrsig, keys = {dnskey_rrset.name: dnskey_rrset})
    except dns.dnssec.ValidationFailure as err:
        print("DNSSec verification failed for zone "+dnskey_rrset.name.to_text())
        return False
    else:
        print("DNSKey for zone "+dnskey_rrset.name.to_text()+" successfully verified")
        return True

def check_ds_rrset(zone_rrset, zone_rrsig, dnskey_rrset):
    try:
        dns.dnssec.validate(rrset = zone_rrset, rrsigset = zone_rrsig, keys = {dnskey_rrset.name: dnskey_rrset})
    except dns.dnssec.ValidationFailure as err:
        print("DNSSec verification failed for zone "+dnskey_rrset.name.to_text())
        return False
    else:
        print("DS/A record for zone "+dnskey_rrset.name.to_text()+" successfully verified")
        return True

def extract_crypto_form_answer(answer):
    for rrset in answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            return next(((rrset, rr) for rr in rrset if rr.flags == 257), (None, None))
    return None, None

def check_zone(parent_ds_rrset, ksk):
    if parent_ds_rrset is None:
        hash_func = 'SHA256'
    else:
        hash_func = hash_functions.get(parent_ds_rrset[0].digest_type, 2)
    
    if parent_ds_rrset is None:
        zone = '.'
    else:
        zone = parent_ds_rrset.name.to_text()
        
    if parent_ds_rrset is None:
        parent_ds_hash_func = root_anchor
    else:
        parent_ds_hash_func = parent_ds_rrset[0].to_text()
    
    try:
        hash1 = dns.dnssec.make_ds(name = zone, key = ksk, algorithm = hash_func).to_text() 
    except dns.dnssec.ValidationFailure as e:
        print("Hash Function {} not supported: {}".format(hash_func, e))
        return False
    else:
        if hash1 == parent_ds_hash_func:
            if zone == '.':
                print("Root Zone "+zone+ " successfully verified")
            else:
                print("Zone "+zone+ " successfully verified")
            return True
        else:
            print("DNSSec verification failed for zone "+zone)
            return False
    
def resolved_storage(answer):
    return next((True for rrset in answer if rrset.rdtype == dns.rdatatype.A), False)
          

def resolver(domain_name, record_type, cname = False, ret_ip = False):
    for root_server_ip_address in root_server_ip_addresses:
        try:
            #Start from the root '.' DNS zone
            root_dnskey_response = recursive_resolve_over_udp('.', dns.rdatatype.DNSKEY, name_server = root_server_ip_address, use_dnssec = True)
            dns_rsp = recursive_resolve_over_udp(domain_name, record_type, name_server = root_server_ip_address, use_dnssec = True)
        except Exception as e:
            continue

        resolved_record = resolved_storage(dns_rsp.answer)
        root_validated, parent_ds_rrset = check_dnssec(dns_rsp, root_dnskey_response, None, resolved_record)
        if not root_validated:
            exit(0)
        #read from Additional section which contains all the IPs
        while(not dns_rsp.answer):            
            if len(dns_rsp.additional) > 0:
                for answer_rrs in dns_rsp.additional:
                    #Consider only IPv4 
                    if answer_rrs[0].rdtype == dns.rdatatype.A:
                        next_ns_ip_addr = answer_rrs[0].address
                        try:
                            #send request to TLD or next set of name servers in the path after verifying the DNSSec information
                            ns_dnskey_response = recursive_resolve_over_udp(parent_ds_rrset.name.to_text(), dns.rdatatype.DNSKEY,
                                name_server = next_ns_ip_addr, use_dnssec = True)
                            ns_dns_rsp = recursive_resolve_over_udp(domain_name, record_type, name_server = next_ns_ip_addr, use_dnssec = True)
                            
                            resolved_record = resolved_storage(ns_dns_rsp.answer)
                            ns_validated, ns_ds_rrset = check_dnssec(ns_dns_rsp, ns_dnskey_response, parent_ds_rrset, resolved_record)
                            if not ns_validated:
                                exit(0)
                            parent_ds_rrset = ns_ds_rrset


                            if cname and ns_dns_rsp.answer and ns_dns_rsp.answer[0].rdtype == dns.rdatatype.CNAME:
                                return ns_dns_rsp
                            elif ret_ip and ns_dns_rsp.answer and ns_dns_rsp.answer[0].rdtype == dns.rdatatype.A:
                                return ns_dns_rsp
                            dns_rsp = ns_dns_rsp
                            break

                        except Exception as err:
                            print(err)
                            pass
            
            elif len(dns_rsp.authority) > 0:
                for answer_rrs in dns_rsp.authority:
                    if answer_rrs.rdtype == dns.rdatatype.SOA:
                        return dns_rsp
                                        
                    ns_domain_name = answer_rrs[0].target.to_text()
                    ns_dns_rsp = resolver(ns_domain_name, 'A', ret_ip = True)
                    if not cname:
                        for auth_rrset in ns_dns_rsp.answer:
                            auth_ip_addr = auth_rrset[0].address             
                            try:
                                auth_dnskey_response = recursive_resolve_over_udp(parent_ds_rrset.name.to_text(), dns.rdatatype.DNSKEY,
                                name_server = auth_ip_addr, use_dnssec = True)
                                auth_dns_rsp = recursive_resolve_over_udp(domain_name, record_type, name_server = auth_ip_addr, use_dnssec = True)

                                resolved_record = resolved_storage(auth_dns_rsp.answer)
                                auth_validated, auth_ds_rrset = check_dnssec(auth_dns_rsp, auth_dnskey_response, parent_ds_rrset, resolved_record)
                                if not auth_validated:
                                    exit(0)

                                parent_ds_rrset = auth_ds_rrset
                                dns_rsp = auth_dns_rsp
                            except Exception as err:
                                print(err)
                                pass
                    else:
                        return ns_dns_rsp
        #in the response if we find A or SOA record, we return the IP as the result of resolution
        for answer_rrs in dns_rsp.answer:
            if dns.rdatatype.from_text(record_type).value == dns.rdatatype.A and (answer_rrs.rdtype == dns.rdatatype.A or answer_rrs.rdtype == dns.rdatatype.SOA):
                return dns_rsp
        #extract CNAME from Answer section to resolve the corresponding IP address
        for answer_rrs in dns_rsp.answer:
            while answer_rrs.rdtype == dns.rdatatype.CNAME:
                cname_domain_name = answer_rrs[0].target.to_text()
                cname_dns_rsp = resolver(cname_domain_name, 'A', cname = True)
                for cname_rrset in cname_dns_rsp.answer:
                    if cname_rrset.rdtype == dns.rdatatype.CNAME:
                        dns_rsp.answer.append(cname_rrset)
                        break
                    else:
                        authoritative_ip = cname_rrset[0].address
                        try:
                            auth_dns_rsp = recursive_resolve_over_udp(cname_domain_name, record_type, name_server = authoritative_ip, use_dnssec = False)
                            if not auth_dns_rsp.answer and auth_dns_rsp.authority:
                                if dns.rdatatype.from_text(record_type).value != dns.rdatatype.A:
                                    dns_rsp.authority.extend(auth_dns_rsp.authority)
                                else:
                                    for auth_rrset in auth_dns_rsp.authority:
                                        auth_domain_name = auth_rrset.name.to_text()
                                        auth_dns_rsp = resolver(auth_domain_name, 'A', cname = True)
                                        if auth_dns_rsp.answer:
                                            break
                            for auth_rrset in auth_dns_rsp.answer:
                                dns_rsp.answer.append(auth_rrset)
                            break
                        except Exception as err:
                            print(err)
                            pass
                break
        break
 
    return dns_rsp
#process the output to be in required format
def make_output(domain_name, dns_rsp, elapsed_time):   
    
    output_string = '----------------------------------------------------------------------\n'
    output_string += 'QUESTION SECTION:\n'
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
                if ans_parts_parts[3] == 'RRSIG':
                    output_string += "\t"
                    output_string += ans_parts_parts[5] 
                    output_string += "\t"
                    output_string += ans_parts_parts[6]
                    output_string += "\t"
                    output_string += ans_parts_parts[7]
                    output_string += "\t"
                    output_string += ans_parts_parts[8]
                    output_string += "\t"
                    output_string += ans_parts_parts[9]
                    output_string += "\t"
                    output_string += ans_parts_parts[10]
                    output_string += "\t"
                    output_string += ans_parts_parts[11]
                    output_string += "\t"
                    output_string += ans_parts_parts[12]
                    output_string += "\t"
                    output_string += ans_parts_parts[13]
                    output_string += "\t"
                    output_string += ans_parts_parts[14]
                    output_string += "\t"
                    output_string += ans_parts_parts[15]
                    output_string += "\t"
                    output_string += ans_parts_parts[15]
                    output_string += "\t"
                    output_string += ans_parts_parts[17]
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
                if ans_parts_parts[3] == 'RRSIG':
                    output_string += "\t"
                    output_string += ans_parts_parts[5] 
                    output_string += "\t"
                    output_string += ans_parts_parts[6]
                    output_string += "\t"
                    output_string += ans_parts_parts[7]
                    output_string += "\t"
                    output_string += ans_parts_parts[8]
                    output_string += "\t"
                    output_string += ans_parts_parts[9]
                    output_string += "\t"
                    output_string += ans_parts_parts[10]
                    output_string += "\t"
                    output_string += ans_parts_parts[11]
                    output_string += "\t"
                    output_string += ans_parts_parts[12]
                    output_string += "\t"
                    output_string += ans_parts_parts[13]
                    output_string += "\t"
                    output_string += ans_parts_parts[14]
                    output_string += "\t"
                    output_string += ans_parts_parts[15]
                    output_string += "\t"
                    output_string += ans_parts_parts[15]
                    output_string += "\t"
                    output_string += ans_parts_parts[17]
                output_string += "\n"
        output_string += "\n"

    
    output_string += "Query time: {} msec\n".format(str(int(elapsed_time * 1000)))
    output_string += "WHEN: {}\n".format(datetime.now().strftime("%a %b %d %H:%M:%S %Y"))
    output_string += "MSG SIZE  rcvd: {}\n".format(sys.getsizeof(dns_rsp.to_text()))
    
    return output_string


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: mydig Domain_Name RR")
        print("This program needs 2 arguments, Domain Name, and RR. RR must be A")
        exit(0)
    

    domain_name = sys.argv[1]
    record_type = sys.argv[2]

    if record_type not in ['A']:
        print("RR type must be A")
        sys.exit(1)
    
    start_time = time.time()
    dns_rsp = resolver(domain_name, record_type)
    elapsed_time = time.time() - start_time

    output= make_output(domain_name, dns_rsp, elapsed_time)
    print(output)