

#  CessTop ---- A Smart Tool written in Python to Parse the Cisco Config File and TopSec Config File 

---

## 1. BackGround

In the production environment of the data centre, there may be replacement work for equipment of different firewall brands such as Cisco and Topsec. In this case, from a practical perspective, there may be a process and requirement of configuration comparison and analysis .

The **CessTop** which is written in Python is coming for these requirements and has perfect performance in practice. It supports Cisco and Topsec config files from current used firewall equipments which are completely different from each other.

Although **CessTop** is still in programmed to make this better, but It already have been equipped with the powerful features to make the process of comparison more easier and reduce the effort of export information of Cisco Config.

<br>

## 2. Usage

1. **Download** and **Unzip** the Entire Project Files into your **PATH**.
2. Use **Python Command** : `python3` to start this tool in your PATH.

**Command Format**:

```shell
$ python3 cesstop.py -s <YOUR CISCO LOG FILE NAME> -c <YOUR TOPSEC LOG FILE NAME>
```

For example:

```shell
$python3 cesstop.py -s FW-1-Cisco.log -c FW-2-TOPSEC.log
```

<br>

## 3. Results

After the this program ends without any errors, there will be **four files**:

+ `./topsec.txt`： All topsec firewall config information in `txt` file;
+ `./cisco_config.csv`:  All separated Cisco firewall config information in `csv` file;
+ `./topsec_config.csv`: All separated TOPSEC firewall config information in `csv` file;
+ `./result.csv`: List the Cisco configuration that does not match the configuration of TOPSEC. ( Comparison Result File)

<br>

## 3. Licences

The open source license of the code of this project refers to MIT.






