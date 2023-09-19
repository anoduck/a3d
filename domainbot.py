import whoisdomain as whois
from tqdm import tqdm
import retry
import asyncio
import os
import sys

from whoisdomain.exceptions import WhoisException

sys.path.append(os.path.expanduser('~/.local/lib/python3.10/site-packages/'))
tld_file = os.path.abspath('./tlds-alpha-by-domain.txt')
avail_file = os.path.abspath('./available.txt')

def retry_on_timeout(exception):
    """ Return True if exception is Timeout """
    return isinstance(exception, whois.WhoisCommandTimeout)


async def get_tld(tld_file):
    with open(tld_file, 'r', encoding='utf8') as rd_tld:
        tld_long_list = list(rd_tld)
        tld_set = set(x for x in tld_long_list if len(x) <= 3)
        rd_tld.close()
        if len(list(tld_set)) > 1:
            return tld_set
        else:
            print('TLD list is empty')
            sys.exit()


# Generate a queue of all possible 3-letter/number domain names
async def gen_names(domains):
    tld_list = list(await get_tld(tld_file))
    domains_queue = set()

    async def gen1():
        for a in range(48, 58):
            for b in range(48, 58):
                for c in range(48, 58):
                    for x in tld_list:
                        domain1 = chr(a) + chr(b) + chr(c) + "." + x
                        if domain1 not in domains:
                            domains_queue.add(domain1)

    async def gen2():
        for d in range(97, 123):
            for e in range(97, 123):
                for f in range(97, 123):
                    for y in tld_list:
                        domain2 = chr(d) + chr(e) + chr(f) + "." + y
                        if domain2 not in domains:
                            domains_queue.add(domain2)

    async def gen3():
        for i in range(97, 123):
            for j in range(48, 58):
                for k in range(97, 123):
                    for z in tld_list:
                        domain3 = chr(i) + chr(j) + chr(k) + "." + z
                        if domain3 not in domains:
                            domains_queue.put(domain3)

    domains_queue = set(await gen1() | await gen2() | await gen3())
    return domains_queue


# Function to check the availability of a domain name
@retry(retry_on_exception=retry_on_timeout, stop_max_attempt_number=5)
async def check_availability(prgs_bar, untested):
    results = []
    for dom in untested:
        save = False
        try:
            reg = whois.query(dom, withPublicSuffix=True)
            if reg:
                prgs_bar.update(1)
                prgs_bar.set_description("Checking %s" % dom)
                print("Domain " + dom + " is already registered.")
                pass
        except whois.WhoisCommandTimeout:
            print('timeout error occurred')
            prgs_bar.update(1)
            prgs_bar.set_description("Checking %s" % dom)
        except whois.WhoisPrivateRegistry:
            prgs_bar.update(1)
            prgs_bar.set_description("Checking %s" % dom)
            pass
        except whois.WhoisQuotaExceeded:
            print('Quota exceeded')
            sys.exit()
        except WhoisException:
            prgs_bar.update(1)
            prgs_bar.set_description("Checking %s" % dom)
            save = True
        if save:
            results.append(dom)
    return results


async def main():
    if os.path.exists(avail_file):
        with open(avail_file, "r", encoding='utf8') as raveable:
            domains = set(raveable)
            raveable.close()
    else:
        domains = set()
    untested = await gen_names(domains)
    prgs_bar = tqdm(total=1000000, desc=('Checking Domains'))
    results = await check_availability(prgs_bar, untested)
    # Open a file to save available domains
    file_wrote = False
    with open(avail_file, "w", encoding='utf8', newline='\n') as faav:
        for fdom in results:
            faav.write(fdom)
            faav.write('\n')
        file_wrote = True
    if file_wrote:
        print("The available domains have been saved to available.txt")


if __name__ == '__main__':
    main()
