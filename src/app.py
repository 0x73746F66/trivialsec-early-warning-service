import json
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network

import validators
from pydantic import BaseModel

import internals
import models
import services.aws
import services.sendgrid
import services.webhook

ALERT_DETAIL = {
    "CharlesHaley": {
        "sshclient": {
            'description': "IP addresses that has been seen initiating an SSH connection to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be SSH server cataloging or conducting authentication attack attempts",
            'summary': "SSH Port Scanning, dictionary attacks, and Bruteforcing Authentication",
            'abuse': "contact@frogfishtech.com",
        },
    },
    "Darklist": {
        "sshclient": {
            'description': "Darklist.de is an IP blacklist that uses multiple sensors to identify network attacks (e.g. SSH brute force) and spam incidents. All reports are evaluated and in case of too many incidents the responsible IP holder is informed to solve the problem. After reporting an incident as solved the IP is removed from the blacklist",
            'summary': "SSH dictionary attacks, and Bruteforcing Authentication",
            'abuse': "https://www.darklist.de/removal.php",
        }
    },
    "TalosIntelligence": {
        "ipreputation": {
            'description': "Talos' IP and Domain Data Center is the world's most comprehensive real-time threat detection network. The data is made up of daily security intelligence across millions of deployed web, email, firewall and IPS appliances. Talos detects and correlates threats in real time using the largest threat detection network in the world spanning web requests, emails, malware samples, open-source data sets, endpoint intelligence, and network intrusions.",
            'summary': "Spam or Malware origin",
            'abuse': "https://www.talosintelligence.com/reputation_center/sender_ip",
        }
    },
    "DataPlane": {
        "sshclient": {
            'description': "IP addresses that has been seen initiating an SSH connection to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be SSH server cataloging or conducting authentication attack attempts",
            'summary': "SSH Port Scanning and Bruteforcing Authentication",
            'abuse': "info@dataplane.org",
        },
        "sshpwauth": {
            'description': "IP addresses that has been seen attempting to remotely login to a host using SSH password authentication. This report lists hosts that are highly suspicious and are likely conducting malicious SSH password authentication attacks",
            'summary': "SSH dictionary attacks",
            'abuse': "info@dataplane.org",
        },
        "dnsrd": {
            'description': "IP addresses that have been identified as sending recursive DNS queries to a remote host. This report lists addresses that may be cataloging open DNS resolvers or evaluating cache entries",
            'summary': "Recursive DNS query cataloging",
            'abuse': "info@dataplane.org",
        },
        "vncrfb": {
            'description': "IP addresses that have been seen initiating a VNC remote frame buffer (RFB) session to a remote host. This report lists hosts that are suspicious of more than just port scanning. These hosts may be VNC server cataloging or conducting various forms of remote access abuse",
            'summary': "Suspicious VNC remote frame buffer (RFB) sessions",
            'abuse': "info@dataplane.org",
        }
    }
}

class EventAttributes(BaseModel):
    ApproximateReceiveCount: int
    SentTimestamp: datetime
    SenderId: str
    ApproximateFirstReceiveTimestamp: datetime


class EventRecord(BaseModel):
    messageId: str
    receiptHandle: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str
    md5OfBody: str
    attributes: EventAttributes
    item: models.FeedStateItem

    def __init__(self, **kwargs):
        kwargs["item"] = json.loads(kwargs["body"])
        super().__init__(**kwargs)


def match_domain(domains: set, data: dict[str, models.ScannerRecord]) -> list[str]:
    return list(
        {
            account_name
            for account_name, scanner_record in data.items()
            for summary in scanner_record.history
            for host in summary.targets
            if host.transport.hostname in domains
        }
    )


def match_email(email: str, accounts: dict[str, models.ScannerRecord]) -> list[str]:
    return []


def update_host(object_key: str, state_item: models.FeedStateItem):
    host = models.Host(**json.loads(services.aws.get_s3(path_key=object_key)))
    if not isinstance(host.threat_intel, list):
        host.threat_intel = []
    new_item = models.ThreatIntel(
        source=state_item.data_model,
        feed_identifier=state_item.key,
        feed_date=state_item.first_seen
    )
    indexed = {}
    for item in host.threat_intel:
        _key = hash(f"{item.source}{item.feed_identifier}{item.feed_date.isoformat()}")
        indexed[_key] = item
    key = hash(f"{new_item.source}{new_item.feed_identifier}{new_item.feed_date.isoformat()}")
    if key not in indexed.keys():
        host.threat_intel.append(new_item)
    host.save()


def update_domains(domains: list[str], state_item: models.FeedStateItem):
    for hostname in domains:
        for object_key in services.aws.list_s3(prefix_key=f"{internals.APP_ENV}/hosts/{hostname}/"):
            if object_key.endswith("latest.json") or (
                    (validators.ipv4(state_item.key) is True or validators.ipv6(state_item.key) is True)
                    and f"/{state_item.key}/" in object_key
                ):
                update_host(object_key, state_item)
                continue
            if validators.ipv4_cidr(state_item.key) is True:
                for ip_address in IPv4Network(state_item.key, strict=False):
                    if ip_address.is_global and f"/{ip_address}/" in object_key:
                        update_host(object_key, state_item)
            if validators.ipv6_cidr(state_item.key) is True:
                for ip_address in IPv6Network(state_item.key, strict=False):
                    if ip_address.is_global and f"/{ip_address}/" in object_key:
                        update_host(object_key, state_item)


def make_data(item: models.FeedStateItem, **extra_data) -> dict:
    feed_item = getattr(models, item.data_model)(**item.data)
    data = ALERT_DETAIL.get(item.data_model, {}).get(feed_item.category, {})
    if hasattr(feed_item, 'asn'):
        data['asn'] = feed_item.asn
    if hasattr(feed_item, 'asn_text'):
        data['asn_text'] = feed_item.asn_text
    if hasattr(feed_item, 'cidr'):
        data['ip_address'] = str(feed_item.cidr)
    if hasattr(feed_item, 'ip_address') and feed_item.ip_address:
        data['ip_address'] = str(feed_item.ip_address)
        if item.data_model == "Darklist":
            data['reference_url'] = f'https://www.darklist.de/view.php?ip={feed_item.ip_address}'
        if item.data_model == "TalosIntelligence":
            data['reference_url'] = f'https://www.talosintelligence.com/reputation_center/lookup?search={feed_item.ip_address}'
    data['last_seen'] = feed_item.last_seen.isoformat()
    return {**data, **extra_data}


def handler(event, context):
    accounts: dict[str, models.MemberAccount] = {}
    ip_index: dict[str, set] = {}
    account_data: dict[str, models.ScannerRecord] = {}
    for host_path in services.aws.list_s3(f"{internals.APP_ENV}/hosts/"):
        _, _, hostname, _, ip_address, *_ = host_path.split('/')
        ip_index.setdefault(ip_address, set())
        ip_index[ip_address].add(hostname)

    for object_path in services.aws.list_s3(f"{internals.APP_ENV}/accounts/"):
        if not object_path.endswith("scanner-record.json"):
            continue
        _, _, account_name, *_ = object_path.split('/')
        accounts[account_name] = models.MemberAccount(name=account_name)
        account_data.setdefault(account_name, models.ScannerRecord(account=accounts[account_name]).load())

    for _record in event["Records"]:
        matches: list[models.MemberAccount] = []
        record = EventRecord(**_record)
        internals.logger.debug(f"Triggered by {record}")
        internals.logger.debug(f"raw {_record}")
        internals.logger.info(f"Queue data {record.item}")
        if not hasattr(models, record.item.data_model):
            internals.logger.error(f"Missing data model: {record.item.data_model}")
            continue

        extra_data = {}
        if validators.ipv4_cidr(record.item.key) is True:
            for ip_address in IPv4Network(record.item.key, strict=False):
                if ip_address.is_global and str(ip_address) in ip_index:
                    webhook_event = models.WebhookEvent.EARLY_WARNING_IP
                    matches.extend(match_domain(ip_index[str(ip_address)], account_data))
                    extra_data.setdefault("domains", [])
                    extra_data["domains"].extend(list(ip_index[str(ip_address)]))
                    extra_data["domains"] = list(set(extra_data["domains"]))
        elif validators.ipv6_cidr(record.item.key) is True:
            for ip_address in IPv6Network(record.item.key, strict=False):
                if ip_address.is_global and str(ip_address) in ip_index:
                    webhook_event = models.WebhookEvent.EARLY_WARNING_IP
                    matches.extend(match_domain(ip_index[str(ip_address)], account_data))
                    extra_data.setdefault("domains", [])
                    extra_data["domains"].extend(list(ip_index[str(ip_address)]))
                    extra_data["domains"] = list(set(extra_data["domains"]))
        elif (validators.ipv4(record.item.key) is True or validators.ipv6(record.item.key) is True) and record.item.key in ip_index:
            webhook_event = models.WebhookEvent.EARLY_WARNING_IP
            matches = match_domain(ip_index[record.item.key], account_data)
            extra_data["domains"] = list(ip_index[record.item.key])
        elif validators.email(record.item.key) is True:
            webhook_event = models.WebhookEvent.EARLY_WARNING_EMAIL
            matches = match_email(record.item.key, accounts)
        elif validators.email(f"nobody@{record.item.key}") is True:
            webhook_event = models.WebhookEvent.EARLY_WARNING_DOMAIN
            matches = match_domain({record.item.key}, account_data)
        else:
            internals.logger.critical(f'No handler for value {record.item.key}')
            continue

        if "domains" in extra_data:
            update_domains(extra_data["domains"], record.item)

        if len(matches) == 0:
            internals.logger.info('No matches')
            continue

        for account_name in matches:
            internals.logger.info(f"matched account {account_name}")
            account = accounts[account_name].load()
            data = {**make_data(record.item), **{**{'account_name': account_name}, **extra_data}}
            services.webhook.send(
                event_name=webhook_event,
                account=account,
                data=data,
            )
            if account.notifications.early_warning:
                internals.logger.info("Emailing alert")
                sendgrid = services.sendgrid.send_email(
                    subject="Early Warning Service (EWS) Alert",
                    recipient=account.primary_email,
                    template="early_warning_service",
                    data=data,
                )
                if sendgrid._content:  # pylint: disable=protected-access
                    res = json.loads(
                        sendgrid._content.decode()  # pylint: disable=protected-access
                    )
                    if isinstance(res, dict) and res.get("errors"):
                        internals.logger.error(res.get("errors"))
