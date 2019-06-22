package main

import (
        "github.com/libgeneratetlscert"
        "log"
}



func main(){

        log("Generate keys for app\n")
	generate_tls_cert("app.ctl.k.e2e.bos.redhat.com","","","")
        log("Keys DOne\n")
}

