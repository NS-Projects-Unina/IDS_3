import pandas as pd
import datetime
import json

# Funzione per analizzare i dati
def analyze_traffic(csv_file):
    try:
        df = pd.read_csv(csv_file, skiprows=1, encoding='ISO-8859-1', sep=',', error_bad_lines=False)
 
        df.columns = df.columns.str.strip()  # Rimuove spazi nei nomi delle colonne
        
        alerts = []
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 1️ Deauthentication Attack 
        if 'BSSID' in df.columns and 'Packets' in df.columns:
            high_packet_macs = df[df['Packets'] > 100]  # Soglia da valutare
            for _, row in high_packet_macs.iterrows():
                alerts.append({
                    "timestamp": now,
                    "connection_id": row['BSSID'],
                    "alert_level": "High",
                    "threat_type": "Deauthentication Attack",
                    "source": row['BSSID']
                })
        
        # 2️ Fake AP  - Stesso ESSID, MAC diverso
        if 'ESSID' in df.columns:
            essid_counts = df.groupby('ESSID')['BSSID'].nunique()
            for essid, count in essid_counts.items():
                if count > 1:
                    alerts.append({
                        "timestamp": now,
                        "connection_id": essid,
                        "alert_level": "Medium",
                        "threat_type": "Fake AP (Evil Twin)",
                        "source": "Multiple BSSIDs"
                    })
        
        # 3️ Beacon Flooding - Troppi SSID in poco tempo
        if df.shape[0] > 50:  # Se ci sono troppi SSID diversi
            alerts.append({
                "timestamp": now,
                "connection_id": "Multiple",
                "alert_level": "High",
                "threat_type": "Beacon Flooding Attack",
                "source": "Unknown"
            })
        
        # 4️ Deauth + Rogue AP - AP scompare e ne appare uno nuovo subito dopo
        if 'Last time seen' in df.columns:
            df['Last time seen'] = pd.to_datetime(df['Last time seen'], errors='coerce')
            last_seen_sorted = df.sort_values('Last time seen')
            for i in range(1, len(last_seen_sorted)):
                if (last_seen_sorted.iloc[i]['ESSID'] == last_seen_sorted.iloc[i-1]['ESSID'] and
                        (last_seen_sorted.iloc[i]['Last time seen'] - last_seen_sorted.iloc[i-1]['Last time seen']).seconds < 30):
                    alerts.append({
                        "timestamp": now,
                        "connection_id": last_seen_sorted.iloc[i]['ESSID'],
                        "alert_level": "Critical",
                        "threat_type": "Deauth + Rogue AP",
                        "source": last_seen_sorted.iloc[i]['BSSID']
                    })
        
        # Nessun attacco rilevato:
        if not alerts:
            return [{"timestamp": now, "connection_id": "None", "alert_level": "Safe", "threat_type": "No Threat Detected", "source": "N/A"}]
        
        return alerts
    
    except Exception as e:
        return [{"timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "connection_id": "Error",
                 "alert_level": "Error",
                 "threat_type": str(e),
                 "source": "Script"}]


if __name__ == "__main__":
    import sys
    #errore passaggio file
    if len(sys.argv) < 2:
        print(json.dumps([{"timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             "connection_id": "Error",
                             "alert_level": "Error",
                             "threat_type": "Nessun file CSV specificato",
                             "source": "Script"}]))
    else:
        csv_file = sys.argv[1]
        results = analyze_traffic(csv_file)
        print(json.dumps(results))
