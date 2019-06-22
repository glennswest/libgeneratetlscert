package main

import (
        . "github.com/glennswest/libgeneratetlscert"
        "log"
)



func main(){

        log.Printf("Generate keys for app\n")
        //Generate_tls_cert(thost string,tvalidFrom string,tvalidFor time.Duration,tkeypath string, dpath string) string
	Generate_tls_cert("*.app.ctl.k.e2e.bos.redhat.com,10.19.114.74","",0,"","certs")
        log.Printf("Keys DOne\n")
}

