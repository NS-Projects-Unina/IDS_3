import pandas as pd
import datetime
import json
from io import StringIO

def analyze_traffic(csv_file, beacon_threshold=4, dos_packet_threshold=50, rapid_reappearance_threshold=30):
    try:
        # Legge e pulisce il file in memoria
        with open(csv_file, 'r', encoding='ISO-8859-1') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        # Trova l'indice in cui inizia la sezione Station
        station_start_idx = None
        for i, line in enumerate(lines):
            if line.startswith("Station MAC"):
                station_start_idx = i
                break
        
        # Divide il file in sezioni AP e Station
        if station_start_idx is not None:
            ap_lines = lines[:station_start_idx]
            station_lines = lines[station_start_idx:]
        else:
            ap_lines = lines
            station_lines = []
        
        alerts = []
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        ### Analisi Sezione AP ###
        if ap_lines:
            ap_data = "\n".join(ap_lines)
            ap_df = pd.read_csv(StringIO(ap_data), sep=';', engine='python', skip_blank_lines=True)
            ap_df.columns = [col.strip() for col in ap_df.columns]
            
            # Pulizia dei dati: rimozione spazi extra nelle colonne critiche
            if 'ESSID' in ap_df.columns:
                ap_df['ESSID'] = ap_df['ESSID'].astype(str).str.strip()
            
            # 1. Fake AP: stesso ESSID trasmesso da BSSID differenti
            #in realtà qui c'è un problema, suppongo nella gestione del formato del file che non ho ancora risolto
            if 'ESSID' in ap_df.columns and 'BSSID' in ap_df.columns:
                essid_counts = ap_df.groupby('ESSID')['BSSID'].nunique()
                for essid, count in essid_counts.items():
                    if pd.notna(essid) and essid != "" and count > 1:
                        alerts.append({
                            "timestamp": now,
                            "alert_level": "Medium",
                            "threat_type": "Fake AP",
                            "source": f"ESSID '{essid}' con {count} BSSID"
                        })
            
            # 2. Beacon Flooding Attack: numero elevato di AP rilevati
            if ap_df.shape[0] > beacon_threshold:
                alerts.append({
                    "timestamp": now,
                    "alert_level": "Medium",
                    "threat_type": "Beacon Flooding Attack",
                    "source": "Sezione AP"
                })
            
            # 3. Deauth + Rogue AP: analisi di riapparizione rapida
            #in realtà qui c'è un problema, suppongo nella gestione del formato del file che non ho ancora risolto, credo sia in comune con quello che blocca il 1 caso

            if 'Last time seen' in ap_df.columns and 'ESSID' in ap_df.columns and 'BSSID' in ap_df.columns:
                ap_df['Last time seen'] = pd.to_datetime(ap_df['Last time seen'], errors='coerce')
                # Raggruppa per ESSID e analizza le differenze temporali
                for essid, group in ap_df.groupby('ESSID'):
                    if pd.notna(essid) and essid != "" and len(group) > 1:
                        group = group.sort_values('Last time seen')
                        time_diffs = group['Last time seen'].diff().dt.total_seconds().fillna(0)
                        if any(time_diffs < rapid_reappearance_threshold):
                            alerts.append({
                                "timestamp": now,
                                "alert_level": "Critical",
                                "threat_type": "Deauth + Rogue AP",
                                "source": f"ESSID '{essid}'"
                            })
            
            # 4. Analisi della durata di visibilità degli AP
            if 'First time seen' in ap_df.columns and 'Last time seen' in ap_df.columns:
                ap_df['First time seen'] = pd.to_datetime(ap_df['First time seen'], errors='coerce')
                ap_df['Last time seen'] = pd.to_datetime(ap_df['Last time seen'], errors='coerce')
                ap_df['duration'] = (ap_df['Last time seen'] - ap_df['First time seen']).dt.total_seconds()
                # Segnala AP con durata di visibilità molto breve (ad esempio, meno di 10 secondi)
                short_duration = ap_df[ap_df['duration'] < 10]
                for _, row in short_duration.iterrows():
                    alerts.append({
                        "timestamp": now,
                        "alert_level": "Low",
                        "threat_type": "AP con visibilità breve",
                        "source": row.get('ESSID')
                    })
        
        ### Analisi Sezione Station ###
        if station_lines:
            station_data = "\n".join(station_lines)
            station_df = pd.read_csv(StringIO(station_data), sep=';', engine='python', skip_blank_lines=True)
            station_df.columns = [col.strip() for col in station_df.columns]
            
            # 1. Dos Attack: numero di pacchetti elevato
            if '# packets' in station_df.columns and 'BSSID' in station_df.columns:
                station_df['# packets'] = pd.to_numeric(station_df['# packets'], errors='coerce').fillna(0)
                high_packet_rows = station_df[station_df['# packets'] > dos_packet_threshold]
                for _, row in high_packet_rows.iterrows():
                    alerts.append({
                        "timestamp": now,
                        "alert_level": "High",
                        "threat_type": "Dos Attack",
                        "source": row.get('Station MAC', 'N/A')
                    })
            
            # 2. Analisi correlata: confronta Power e # packets per individuare stazioni sospette, possibile sistema in ascolto
            if 'Power' in station_df.columns and '# packets' in station_df.columns:
                station_df['Power'] = pd.to_numeric(station_df['Power'], errors='coerce')
                station_df['# packets'] = pd.to_numeric(station_df['# packets'], errors='coerce')
                suspicious_stations = station_df[(station_df['Power'] > -60) & (station_df['# packets'] < 5)]
                for _, row in suspicious_stations.iterrows():
                    alerts.append({
                        "timestamp": now,
                        "alert_level": "Medium",
                        "threat_type": "Stazione sospetta (Power/Pacchetti)",
                        "source": row.get('Station MAC', 'N/A')
                    })
        
        if not alerts:
            return [{
                "timestamp": now,
                "alert_level": "Safe",
                "threat_type": "No Threat Detected",
                "source": "N/A"
            }]
        
        return alerts

    except Exception as e:
        return [{
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_level": "Error",
            "threat_type": str(e),
            "source": "Script"
        }]

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(json.dumps([{
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_level": "Error",
            "threat_type": "Nessun file CSV specificato",
            "source": "Script"
        }]))
    else:
        csv_file = sys.argv[1]
        results = analyze_traffic(csv_file)
        print(json.dumps(results))
