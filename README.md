## Blue

Blue is a web-panel designed to make reconnaissance faster and easier accessible. Blue currently supports:  

* Subdomain Enumeration
* Google Dorking
* Email Harvesting
* Software Detection
* Data Leak Lookup (via WeLeakInfo)

We were initially going to host this ourself, but we simply don't have the time or resources to do so. For that reason, we have removed certain features from the public open-source version (employee scraping, returning actual data in the leak lookups, etc) since we aren't going to be hosting it ourself and cannot monitor for any misuse of these functionalities. We refuse to be responsible for such things -- hence why we have removed these features from the public version.  

We will still add new features, so if you have suggestions then let us know or send in a PR!  

### Disclaimer

Blue has been designed for use against targets you are AUTHORIZED to test against. The authors of Blue are not responsible for any individual or group using this tool for reconnaissance for illegal activity.


![Blue](https://i.imgur.com/lBI4hdh.png)

<hr>

To use email harvesting, you must add your Hunter.io API key in `/app/home/routes.py`on line 179.

## Setup (with SQLite database)

#### Clone this repository:

```git clone https://github.com/0days/Blue```  

#### Install requirements:  

```pip install -r requirements.txt```  

#### Export and run:

```
export FLASK_APP=blue.py  (nix)  
set FLASK_APP=blue.py  (windows)  
flask run --host=0.0.0.0  
```
## Setup (with PostgreSQL database - Ubuntu)  

#### Clone this repository:

```git clone https://github.com/0days/Blue```  

#### Install requirements:  

```pip install -r requirements.txt```

#### Setup your PostgrelSQL database
```
sudo apt-get update  
sudo apt-get install -y postgresql libpq-dev  
sudo -u postgres psql -c "CREATE DATABASE blue;"  
sudo -u postgres psql -c "CREATE USER blue WITH PASSWORD 'your-password';"  
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE blue TO blue;"  
```

#### Export and run
```
export BLUE_CONFIG_MODE=Production  
export BLUE_DATABASE_PASSWORD=your-password  
export FLASK_APP=blue.py    
flask run --host=0.0.0.0  
```
<hr>  
  
## Credits

Daley Bee - https://twitter.com/daley  
Dominik Penner - https://twitter.com/zer0pwn  
Jake Bolam - https://twitter.com/jake_sec  
