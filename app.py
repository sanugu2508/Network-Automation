from flask import Flask, render_template,request, redirect
import subprocess
import vyatta_access
import os
from datetime import datetime
import get_config_vyatta
import ipaddress
import get_asa_routes
import asa_connect
import vlan_details_find



app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')




@app.route("/check_vyatta_access", methods=["GET", "POST"])
def check_vyatta_access():
    lastmodified= os.stat('vyatta.txt').st_mtime

    modified = datetime.fromtimestamp(lastmodified)
    modified = modified.strftime("(%a) %-d %b %Y, %I:%M %p")
    output = ' '

    if request.method == "POST":

        sip = str(request.form.get('sourceip'))
        dip = str(request.form.get('destinationip'))
        realtime = str(request.form.get('realtime'))
        sip = sip.replace("'",'')
        dip = dip.replace("'",'')
        #print (sip,dip,realtime)
        try:
            ipaddress.IPv4Address(unicode(sip)) and ipaddress.IPv4Address(unicode(dip))
            if realtime=='True':
                username = str(request.form.get('username'))
                password = str(request.form.get('password'))
                #print (sip,dip,realtime,username,password)
                get_config_vyatta.realtime_config()
                output = vyatta_access.matchips(sip,dip)
                output =  output.split('\n')
   
            elif  realtime=='None':
                output = vyatta_access.matchips(sip,dip)
                output =  output.split('\n')
        except Exception as unknown_error:
            output = [str(unknown_error)]
        
    return render_template("check_vyatta_access.html", output = output, modified = modified)

@app.route("/check_asa_access", methods=["GET", "POST"])
def check_asa_access():
    output = ' '
    if request.method == "POST":
        try:

            sip = str(request.form.get('sourceip'))
            dip = str(request.form.get('destinationip'))
            protocol = str(request.form.get('protocol'))
            port = str(request.form.get('port'))
            fwip = str(request.form.get('fws'))
            sip = sip.replace("'",'')
            dip = dip.replace("'",'')
            nameifsource = get_asa_routes.iface_find(sip,fwip)
            nameifdest = get_asa_routes.iface_find(dip,fwip)
            if nameifsource == nameifdest:
                output = ['Error : Given source and Destinations are behind same interface. {sip} : {nameifsource}, {dip} : {nameifdest} '.format(sip=sip,nameifsource=nameifsource,dip=dip,nameifdest=nameifdest)]
            else:
                #command = 'packet-tracer input {nameif} {protocol} {sip} 12345 {dip} {port}'.format(nameif=nameifsource, protocol=protocol,sip=sip,dip=dip,port=port)
                output = asa_connect.asa_connect(fwip,nameifsource,sip,dip,protocol,port)
                output =  output.split('\n')
        except Exception as unknown_error:
            output = [str(unknown_error)]
            
    return render_template("check_asa_access.html", output = output)

@app.route("/vlan_find", methods=["GET", "POST"])
def vlan_find():
    output = ' '
    if request.method == "POST":
        try:

            sip = str(request.form.get('sourceip'))
            sip = sip.replace("'",'')
	    #print sip
            output = vlan_details_find.fetch_vlan(sip)

	    output =  output.split('\n')
        except Exception as unknown_error:
            output = [str(unknown_error)]
            
    return render_template("vlan_find.html", output = output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='8000', debug=True)
