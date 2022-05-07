**AES256 whitebox encryption**

  This small code take whitebox data from arbitrary binary file and perform an AES256 CFB encryption on input data.

*Compilation*
	

    gcc main.c -o aes_whitebox

 *Usage*

aes_whitebox binary_file iv input

       binary_file : file for recovering AES whitebox compiled data
       iv          : initialisation vector to be searched on binary file and used as IV
       input       : data to encrypt

Output is provided as hex string
