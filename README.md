

#  CessTop ---- A Smart Tool written in Python to Parse and Compare the Cisco Firewall Config File with TopSec Firewall Config File 

---

## 1. BackGround

In the production environment of the data centre, there may be replacement work for equipment of different firewall brands such as Cisco and Topsec. In this case, from a practical perspective, there may be a process and requirement of configuration comparison and analysis to make replacement of firewall equipment more easy and reliable .

The **CessTop** which is written in Python is coming for these requirements and has perfect performance in practice. It supports Cisco and Topsec config files from current used firewall equipments which are completely different from each other.

Although **CessTop** is still in programmed to make this better, but It already have been equipped with the powerful features to make the process of comparison more easier and reduce the effort of export information of Cisco Config.

**Features**:

+ Export all Cisco (access-list) config from Cisco Config File from Cisco Firewall Machine.
+ Export all Topsec (firewall-policy) config from TopSec Config File from TopSec.
+ Compare Cisco Firewall Config with Topsec Firewall Config and Export the Missing Config

**Explanation**:

+ Cisco Firewall Machine:

  To obtain the Cisco Firewall Config, you should run Command: `show run` in Cisco Firewall Machine Management console.

  And:

  Store All the output from console.

+ TopSec Firewall Machine:

  To obtain the TopSec Firewall Config, you should run Command: `show` in TopSec Firewall Machine Management console.

  And:

  Store All the output from console.

<br>

## 2. Usage

>**Runtime Environment**:
>
>+ Only can be executed in Unix Operating System, not supported for Windows yet.
>+ Only Python 3.5x and Newer
>
>**Reliable Package**:
>
>+ **Pandas**  ----------  [Python Data Analysis Library](https://pandas.pydata.org/)
>+ **argparse**  --------- [Python Command Line parameters parser](https://docs.python.org/3/library/argparse.html)

1. **Download** and **Unzip** the Entire Project Files into your **PATH**.
2. Use **Python Command** : `python3` to start this tool in your PATH.

**Command Format**:

```shell
$ python3 cesstop.py -s <YOUR CISCO CONFIG FILE NAME> -c <YOUR TOPSEC CONFIG FILE NAME>
```

For example:

```shell
$python3 cesstop.py -s FW-1-Cisco.log -c FW-2-TOPSEC.log
```

<br>

## 3. Results

In Version 2.0+, this tool will create a new result folder named "output" to store all the result files (.csv file).

After the this program ends without any errors, there will be **Three files**:

+ `./output/cisco_config.csv` :  contains all the Cisco firewall (access-list) config.
+ `./output/topsec_config.csv`: contains all the Topsec firewall (firewall-lolicay) config.
+ `./output/result.csv`:  contains all the missing Cisco firewall config compared with the TopSec Config file.

<br>

## 4. Versions

+ **2021 - 05 - 04**

  Version 2.1:

  + Big Update for Generating Pandas DataFrame - This tool runs 1000x more efficiently.
  + Use `asyncio` to improve the speed of File IO - IO speed Increasd by about 100 times.
  + Refactored the Entry Code using `argparse` .

+ **2021 - 04 - 01**

  Version 2.0: 

  + Refactored all the code, implemented the multi-process feature for the tool.
  + improved the overall operating performance, And some improvements to the console display.

+ **2021 - 03 - 26**   

  Version 1.0:  Core Functions Finished

<br>

## 5. Licences

The open source license of the code of this project refers to MIT.





