import sqlite3
conn = sqlite3.connect('pandora.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS NetworkData
       (Hostname TEXT, 
       Location TEXT, 
       Subnet TEXT, 
       CIDR TEXT, 
       Metric TEXT, 
       Origin TEXT, 
       Next_Hop TEXT, 
       Zone TEXT, 
       VRF TEXT);''')

entry = [Hostname, Location, match_object.group(2), ip_cidr[1], match_object.group(3), match_object.group(1), match_object.group(4), match_object.group(6), 'default']
print(entry)
cursor.execute('''INSERT INTO NetworkData (Hostname, Location,Subnet,CIDR,Metric,Origin,Next_Hop, Zone, VRF) VALUES (?,?,?,?,?,?,?,?,?)''',entry)
conn.commit()
conn.close()
