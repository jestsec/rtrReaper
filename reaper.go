package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"

	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/jonlaing/htmlmeta"
)

//try exploit arrays
var teDlinks = []string{}
var teLinksys = []string{}
var generic = []string{}
var ruckus = []string{}
var rtrsrc = []string{"D-LINK", "Linksys", "RouterOS", "Router", "Ruckus"}

func finder(ip string) {
	//create http client and set timeout
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	//make request to ip
	resp, err := client.Get(fmt.Sprintf("%s", ip))
	if err != nil {

		return
	}
	if resp.StatusCode == 200 {

		//search html title for matches
		getTitle := htmlmeta.Extract(resp.Body)
		dlinkSrc := strings.Contains(getTitle.Title, "D-LINK")
		genericSrc := strings.Contains(getTitle.Title, "Router")
		ruckusSrc := strings.Contains(getTitle.Title, "Ruckus")
		//IF CERTAIN STRINGS FOUND. PRINT MESSAGE , AND APPEND IP TO SPECIFIED LISTS ABOVE
		if getTitle.Title == "Linksys Smart Wi-Fi" {
			fmt.Println("Linksys Found!")
			teLinksys = append(teLinksys, ip)
		}
		if dlinkSrc == true {
			fmt.Println("D-Link Found!")
			teDlinks = append(teDlinks, ip)
		}

		if genericSrc == true {
			fmt.Println("Generic Router Found")
			generic = append(generic, ip)
		}

		if ruckusSrc == true {
			fmt.Println("Ruckus Device Found")
			ruckus = append(ruckus, ip)
		}
		color.Set(color.FgBlue)
		fmt.Println(fmt.Sprintf("%s:%s", ip, getTitle.Title))
		color.Unset()
	}
}

func linksys_Default_Admin(ip string) {
	var jsonStr = []byte(`{}`)
	crturl := fmt.Sprintf("%s/JNAP/", ip)
	type defaultpass struct {
		output                 string
		isAdminPasswordDefault string
	}

	req, _ := http.NewRequest("POST", crturl, bytes.NewBuffer(jsonStr))
	req.Header.Add("X-JNAP-ACTION", "http://cisco.com/jnap/core/IsAdminPasswordDefault")
	req.Header.Add("Content-Type", "application/json")
	var client = http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Request Error Occured")
		return
	}

	var data2 defaultpass

	if err != nil {
		return
	}
	bodyRead, _ := ioutil.ReadAll(resp.Body)
	jsonerr := json.Unmarshal(bodyRead, &data2)
	if jsonerr != nil {
		fmt.Println("Json Error Occurred")
		return
	}
	stringBody := string(bodyRead)
	if strings.Contains(stringBody, "true") {
		fmt.Println("------------------------------")
		fmt.Println("Default Admin Password Found")
		fmt.Printf("%s\n", ip)
		fmt.Println("------------------------------")
	}

}

func check(cidr string, port string) {
	isIP := net.ParseIP(cidr)
	valid := map[string]bool{"80": true, "8080": true, "8008": true, "443": true}
	if isIP != nil {
		color.Red("%s is not a subnet \n", isIP)
		fmt.Println("Usage: ./reaper 192.168.1.1/24 80")
		os.Exit(0)
	} else if valid[port] != true {
		color.Red("Not a valid port")
		fmt.Printf("Please use one of the following ports:\n")
		for ports := range valid {
			fmt.Println(ports)
		}
		fmt.Println("Usage: ./reaper 192.168.1.1/24 80")
		os.Exit(0)
	}

}

func main() {

	if len(os.Args) <= 2 {

		color.Set(color.FgHiRed)
		color.Red("Not enough arguemnts given ")
		fmt.Println("Usage: ./reaper 192.168.1.1/24 80")
		os.Exit(0)
	}
	//args here
	rtr_Asn := os.Args[1]
	port := os.Args[2]
	check(rtr_Asn, port)
	color.Set(color.FgHiBlue)
	figure.NewFigure("RTR Reaper", "slant", true).Print()
	color.Unset()
	time.Sleep(3 * time.Second)

	re2 := regexp.MustCompile(`(\d+\.\d+.\d+.\d+)/(\d+)`)
	matches2 := re2.FindAllString(rtr_Asn, -1)

	var scythe = make(chan int, 100)
	for _, ip := range matches2 {
		_, ipv4Net, err := net.ParseCIDR(ip)
		if err != nil {
			log.Fatal(err)
		}

		mask := binary.BigEndian.Uint32(ipv4Net.Mask)
		start := binary.BigEndian.Uint32(ipv4Net.IP)
		finish := (start & mask) | (mask ^ 0xffffffff)

		color.Set(color.FgHiCyan)
		fmt.Printf("Reaping %s on port %s\n", rtr_Asn, port)
		color.Unset()

		for i := start; i <= finish; i++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)
			if port == "443" {

				makeUrl := fmt.Sprintf("https://%s:%s", ip, port)
				scythe <- 1
				go func() {
					finder(makeUrl)
					<-scythe
				}()
			} else {
				makeUrl := fmt.Sprintf("http://%s:%s", ip, port)

				scythe <- 1
				go func() {
					finder(makeUrl)
					<-scythe
				}()
			}

		}

	}
	color.Set(color.FgHiBlue)

	//IF LIST IS NOT EMPTY THEN GO THROUGH LISTS
	if len(teDlinks) > 0 {
		fmt.Println(len(teDlinks), "Dlink Devices Found")
		for _, dlinksFound := range teDlinks {
			fmt.Println(dlinksFound)
			color.Unset()

		}
	}
	//start exploiting dlinks

	lf := len(teLinksys)
	color.Set(color.FgHiBlue)
	fmt.Println(lf, "Linksys Device Found")
	color.Unset()

	//list generic devices
	genList := len(generic)
	color.Set(color.FgBlue)
	fmt.Println(genList, "Generic Devices Found")
	color.Unset()
	for _, genericsFound := range generic {
		fmt.Println(genericsFound)
	}
	//start exploiting linksys devices
	for _, linksysFound := range teLinksys {
		color.Set(color.FgHiBlue)
		fmt.Println(linksysFound)
		color.Unset()
		fmt.Println("Starting Password Exploit For Linksys Devices")
		linksys_Default_Admin(linksysFound)
	}

	for _, ruckusFound := range ruckus {
		color.Set(color.FgHiBlue)
		fmt.Println("Ruckus Devices Found")
		fmt.Println(ruckusFound)
		color.Unset()

	}

}
