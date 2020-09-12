# AZ5
MongoDB SCRAM-SHA-1 bruteforcer


```Usage of ./mongobrute_hash:
  -passfile string
    	location of password file, use '-' for STDIN
  -salt string
    	Salt
  -serverkey string
    	Server Key
  -threads int
    	number of workers per machine (default 8)
  -username string
    	Username
```

* -passfile Can be S3 bucket path, such as s3://bucket/object, the object must be gzipped. 
* -salt and -serverkey must be in it's original Base64 encoded format.

##Example:
./mongobrute -salt RMsRzAD1ONlZN19sRjqRpw== -username admin -serverkey YsIpaLeJo28RvHXf37Pk4Obe/jE= -passfile dict.txt
