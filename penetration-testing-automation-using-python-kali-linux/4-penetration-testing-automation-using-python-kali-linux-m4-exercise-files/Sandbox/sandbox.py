from netaddr import IPRange,IPNetwork,IPAddress





def _get_ip_addresses(input_data):
    ip_addresses = []
    
    if "-" in input_data:
        input_data_splitted = input_data.split('-')
        first_ip_address = input_data_splitted[0]
        first_ip_address_splitted = first_ip_address.split('.')
        second_ip_address = '%s.%s.%s.%s'%(first_ip_address_splitted[0],first_ip_address_splitted[1],
                                           first_ip_address_splitted[2],input_data_splitted[1])
        
        ip_addresses=IPRange(first_ip_address,second_ip_address)
        
    elif "," in input_data:
        ip_addresses = input_data.split(',')
        
    else:
        ip_addresses = IPNetwork(input_data)
        
    return ip_addresses
    


#input_data = "10.0.0.100-120"
#input_data = "10.0.0.1"
#input_data = "10.0.0.1/24"
input_data = "10.0.0.1,10.0.0.3"

for ip_item in _get_ip_addresses(input_data):
    print "ping " + str(ip_item)