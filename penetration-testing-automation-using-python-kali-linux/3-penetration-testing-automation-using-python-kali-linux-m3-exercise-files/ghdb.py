import urllib2
import time
from BeautifulSoup import BeautifulSoup
import HTMLParser

def extract_google_dorks(start_item_number,latest_item_number):
    #log file
    log_file_name = "GhdbResults_" + str(start_item_number) + "_" + str(latest_item_number) + ".txt"
    log_file = open(log_file_name, "a")
    #failed attempts counter
    failed_attempts_counter = 0
    
    for page_number in range(start_item_number,latest_item_number):
        
        current_url = 'http://www.exploit-db.com/ghdb/' + str(page_number) + '/'
    
        print "Downloading " + current_url
    
        try:
    
            # Construct the HTTP Request
            item_request = urllib2.Request(current_url)
            item_request.add_header('user-agent','Mozilla/5.0 (X11; Linux i686; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4')
    
            # Get the HTTP Response aka HTML page
            item_response = urllib2.urlopen(item_request, timeout=7)
            item_content = item_response.read() 
    
            parsed_html = BeautifulSoup(item_content)
            table = parsed_html.body.find('table', {'class': 'category-list'})
            first_td = table.findChild('td')
            html_parser = HTMLParser.HTMLParser()        
    
            # Extract Dorks Data
            item_google_dork_td = first_td.findNext('td')
            item_google_dork = "Google Dork: " + item_google_dork_td.find('a').get('href') + "\n"
    
    
            item_date_added_td = item_google_dork_td.findNext('td')
            item_date_added = html_parser.unescape(item_date_added_td.text) + "\n"
    
            item_desc_td = item_date_added_td.findNext('td')
            item_desc = "Description: " + html_parser.unescape(item_desc_td.text) + "\n"
    
            # Save the results        
            log_file.write(item_date_added + item_desc + item_google_dork + "\n-------------------------------------------------------------\n")
            item_response.close()
    
            #reset counter
            failed_attempts_counter = 0
    
            print "[+]FINISHED"
    
        except Exception,e:
            print "Exception:" + str(e)
            print "Error retrying in 3 seconds."
            time.sleep(3)     
            failed_attempts_counter += 1
    
            if failed_attempts_counter == 5:
                print "Something is wrong,exiting..."
                log_file.close()
                exit(0)     
    
    log_file.close()
    print "[+] Congrats! the application report is saved: " + log_file_name

def main():
    extract_google_dorks(900,906)
    
if __name__ == '__main__':
    main()