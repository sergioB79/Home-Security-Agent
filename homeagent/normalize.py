import json
import xml.etree.ElementTree as ET


def parse_sysmon_xml(xml_str):
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    root = ET.fromstring(xml_str)

    system = root.find("e:System", ns)
    event_id = int(system.find("e:EventID", ns).text)
    record_id = int(system.find("e:EventRecordID", ns).text)
    ts = system.find("e:TimeCreated", ns).attrib.get("SystemTime")

    data = {}
    for d in root.findall("e:EventData/e:Data", ns):
        name = d.attrib.get("Name")
        data[name] = d.text or ""

    return {
        "event_id": event_id,
        "record_id": record_id,
        "ts": ts,
        "data": data,
    }
