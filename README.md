### EGA python client version 3.0.0
pyEGA3 uses the EGA REST API to download authorized datasets and files

Currently works only with Python3

### REQUIREMENTS
Python "requests" module
http://docs.python-requests.org/en/master/
pip3 install requests

-------------------------------------------------------------------------
usage: pyega3.py [-h] [-d] -cf CREDENTIALS_FILE [-c CONNECTIONS]
                  {datasets,files,fetch} ...

Download from EMBL EBI's EGA (European Genome-phenome Archive)

positional arguments:
  {datasets,files,fetch}
                        subcommands
    datasets            List authorized datasets
    files               List files in a specified dataset
    fetch               Fetch a dataset or file

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Extra debugging messages
  -cf CREDENTIALS_FILE, --credentials-file CREDENTIALS_FILE
                        JSON file containing credentials
                        e.g.{'username':'user1','password':'toor'}
  -c CONNECTIONS, --connections CONNECTIONS
                        Download using specified number of connections
                        
                        
-------------------------------------------------------------------------
  
Credentials file supposed to be in json format e.g:
{
    "username": "my.email@domain.edu",
    "password": "mypassword",    
}

Your username and password are provided to you by EGA.


