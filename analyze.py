import pandas as pd
import datetime
import json
from io import StringIO

def analyze_traffic(csv_file):
    try:
        # Legge tutto il file in memoria
        with open(csv_file, 'r', encoding='ISO-8859-1') as f:
            lines = f.readlines()

        # Rimuove righe vuote ed elimina spazi bianchi
        lines = [line.strip() for line in lines if line.strip() != '']

        # Trova l'indice in cui inizia la sezione Station (ricerca della riga che inizia con "Station MAC")
        station_start_idx = None
        for i, line in enumerate(lines):
            if line.startswith("Station MAC"):
                station_start_idx = i
                break

        # Se la sezione Station è presente, suddivide il file in due parti
        if station_start_idx is not None:
            ap_lines = lines[:station_start_idx]
            station_lines = lines[station_start_idx:]
        else:
            ap_lines = lines
            station_lines = []

        alerts = []
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        ### Sezione AP ###
        if ap_lines:
            # Unisce le righe in una stringa e legge i dati
            ap_data = "\n".join(ap_lines)
            ap_df = pd.read_csv(StringIO(ap_data), sep=';', engine='python', skip_blank_lines=True)
            # Rimuove spazi extra dai nomi delle colonne
            ap_df.columns = [col.strip() for col in ap_df.columns]

            # Pulisce i valori di ESSID per rimuovere eventuali spazi extra
            if 'ESSID' in ap_df.columns:
                ap_df['ESSID'] = ap_df['ESSID'].astype(str).str.strip()

            # 2️ Fake AP (Evil Twin): stesso ESSID trasmesso da BSSID differenti
            if 'ESSID' in ap_df.columns and 'BSSID' in ap_df.columns:
                essid_counts = ap_df.groupby('ESSID')['BSSID'].nunique()
                for essid, count in essid_counts.items():
                    if pd.notna(essid) and essid != "" and count > 1:
                        alerts.append({
                            "timestamp": now,
                            "alert_level": "Medium",
                            "threat_type": "Fake AP (Evil Twin)",
                            "source": f"ESSID '{essid}' con {count} BSSID"
                        })

            # 3️ Beacon Flooding Attack: se il numero di AP rilevati è superiore a un certo valore
            if ap_df.shape[0] > 4:  # soglia valutata solo per scopi dimostrativi
                alerts.append({
                    "timestamp": now,
                    "alert_level": "High",
                    "threat_type": "Beacon Flooding Attack",
                    "source": "Sezione AP"
                })

            # 4️ Deauth + Rogue AP: AP con lo stesso ESSID che "scompaiono" e ricompaiono in meno di 30 secondi
            if 'Last time seen' in ap_df.columns and 'ESSID' in ap_df.columns and 'BSSID' in ap_df.columns:
                ap_df['Last time seen'] = pd.to_datetime(ap_df['Last time seen'], errors='coerce')
                # Raggruppa per ESSID e analizza ciascun gruppo
                for essid, group in ap_df.groupby('ESSID'):
                    if pd.notna(essid) and essid != "" and len(group) > 1:
                        group = group.sort_values('Last time seen')
                        previous_row = None
                        for idx, row in group.iterrows():
                            if previous_row is not None:
                                time_diff = (row['Last time seen'] - previous_row['Last time seen']).total_seconds()
                                if time_diff < 30:
                                    alerts.append({
                                        "timestamp": now,
                                        "alert_level": "Critical",
                                        "threat_type": "Deauth + Rogue AP",
                                        "source": row['BSSID']
                                    })
                            previous_row = row

        ### Sezione Station ###
        if station_lines:
            station_data = "\n".join(station_lines)
            station_df = pd.read_csv(StringIO(station_data), sep=';', engine='python', skip_blank_lines=True)
            station_df.columns = [col.strip() for col in station_df.columns]

            # 1️ Dos Attack: se il numero di pacchetti supera una soglia
            if '# packets' in station_df.columns and 'BSSID' in station_df.columns:
                station_df['# packets'] = pd.to_numeric(station_df['# packets'], errors='coerce').fillna(0)
                high_packet_rows = station_df[station_df['# packets'] > 50]  # soglia definita solo per scopi dimostrativi
                for _, row in high_packet_rows.iterrows():
                    alerts.append({
                        "timestamp": now,
                        "alert_level": "High",
                        "threat_type": "Dos Attack",
                        "source": row['BSSID']
                    })

        if not alerts:
            return [{
                "timestamp": now,
                "connection_id": "None",
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
