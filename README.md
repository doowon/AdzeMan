# AdzeMan
Another version of [Axeman](https://github.com/CaliDog/Axeman).

### Purpose
AdzeMan is another version of Axeman, a utility to download certificates from Certificate Transparencies (CTs) using multi-processing (aiproceesing) and concurreny (asyncio) with more features that I need for my current project.

### New features
1. Cryptography library: It uses [cryptography.io](https://cryptography.io/) rather than [pyOpenSSL](https://pypi.org/project/pyOpenSSL/) because the cyptography.io library is strongly recommended to use over pyOpenSSL.
2. Resuming: Axeman does not have the resume feature after the program stops. Rather we are supposed to manually figure out the last offset number and pass it as a parameter when resuming Axeman. But this program automatically traverses all csv files that we have downloaded and updates a new list to newly download. 
3. Block size: Some CTs such as *Rocketeer* are supposed to return one certificate rather than the maximum number of certificates (e.g., 32 certificates) when more than the maximum number of certificates are requested. As an argument, you can pass the block size you prefer. 
4. Fail: Sometimes you may fail in downloading certificates from CTs due to network errors. In this case, rather than try again, just dump the failed certificate offset numbers in a CT. After you are done with downloading all certificates from a CT, you can resume downloading the downloading-failed certificates.
