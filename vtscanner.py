import argparse
import sys
import virustotal


title = """
 _    ________   _____                                 
| |  / /_  __/  / ___/_________ _____  ____  ___  _____
| | / / / /     \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
| |/ / / /     ___/ / /__/ /_/ / / / / / / /  __/ /    
|___/ /_/     /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                            
                   Developed By: Elif Nur KARAKOC                   
"""


def main():
    print(title)
    desc = 'It provides URL and file query by using VirusTotal API.'
    parser = argparse.ArgumentParser(description=desc, prog='virustotal2.py')
    parser.add_argument('--apikey', type=str, required=True, help='VirusTotal API Key.')
#    parser.add_argument('--dir', type=str,help="Directory location to save the result json.")  
    parser.add_argument('--filescan',  type=str, help="Upload and scan a file")
    parser.add_argument('--filereport',  type=str, help="Report a file")
    parser.add_argument('--urlreport', type=str, help="Report an URL")
#    parser.add_argument('--report', type=str, help="Save the result json file")
    args = parser.parse_args()


    apikey=args.apikey
    if args.filescan:
      result_hash=virustotal.file_scan(args.filescan,apikey)
      if len(result_hash)>0:
        virustotal.file_scan_result(result_hash,apikey)
    if args.urlreport:
      virustotal.url_report(args.urlreport,apikey)
    if args.filereport:
      result_hash=virustotal.file_scan_result(args.filereport,apikey)

#    report_location=""
#    if args.dir:
#      report_location = args.dir
#      if os.path.isdir(report_location):
#          report_location = os.path.abspath(args.dir)
#      else:
#          print('Save location doesn\'t exist or not a directory')
#          sys.exit()


#        if args.report :
#          virustotal.report_json(report_location)


if __name__ == '__main__':
    sys.exit(main())