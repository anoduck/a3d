from asyncio.tasks import as_completed
import whoisdomain as whois
import alive_progress
from retry import retry
import asyncio
import os
import sys

from whoisdomain.exceptions import WhoisCommandTimeout, WhoisException

sys.path.append(os.path.expanduser('~/.local/lib/python3.10/site-packages/'))
tld_file = os.path.abspath('./tlds-alpha-by-domain.txt')
avail_file = os.path.abspath('./available.txt')


def get_tld(tld_file):
    with open(tld_file, 'r', encoding='utf8', newline='\n') as rd_tld:
        tld_long_list = rd_tld.readlines()
        tld_set = []
        for x in tld_long_list:
            if len(x) <= 3:
                nx = x.rstrip().lower()
                tld_set.append(nx)
        if len(tld_set) > 1:
            return tld_set
        else:
            print('TLD list is empty')
            sys.exit()


# Generate a queue of all possible 3-letter/number domain names
async def gen_names(domains):
    tld_list = list(get_tld(tld_file))

    def gen1():
        dlist1 = list()
        for a in range(48, 58):
            for b in range(48, 58):
                for c in range(48, 58):
                    for x in tld_list:
                        domain1 = chr(a) + chr(b) + chr(c) + "." + x
                        if domain1 not in domains:
                            dlist1.append(domain1)
        return dlist1

    def gen2():
        dlist2 = list()
        for d in range(97, 123):
            for e in range(97, 123):
                for f in range(97, 123):
                    for y in tld_list:
                        domain2 = chr(d) + chr(e) + chr(f) + "." + y
                        if domain2 not in domains:
                            dlist2.append(domain2)
        return dlist2

    def gen3():
        dlist3 = list()
        for i in range(97, 123):
            for j in range(48, 58):
                for k in range(97, 123):
                    for z in tld_list:
                        domain3 = chr(i) + chr(j) + chr(k) + "." + z
                        if domain3 not in domains:
                            dlist3.append(domain3)
        return dlist3

    coro = await asyncio.gather(asyncio.to_thread(gen1), asyncio.to_thread(gen2), asyncio.to_thread(gen3))
    return coro


# Function to check the availability of a domain name
@retry(exceptions=whois.WhoisCommandTimeout, tries=5, delay=3, jitter=(3, 5))
@retry(exceptions=whois.WhoisQuotaExceeded, tries=5, delay=5, backoff=5, jitter=(1, 3))
async def bitch(queue, bar):
    dom = await queue.get()
    save = False
    up_prgs = False
    try:
        reg = whois.query(dom, withPublicSuffix=True)
        if reg:
            up_prgs = True
    except whois.WhoisCommandTimeout:
        raise Exception('Timeout Occurred')
    except whois.WhoisPrivateRegistry:
        up_prgs = True
    except whois.WhoisQuotaExceeded:
        raise Exception('Quota Exceeded')
    except WhoisException:
        save = True
        up_prgs = True
    if save:
        return dom
    if up_prgs:
        queue.task_done()
        bar()


async def check_doms(untested):
    queue = asyncio.Queue()
    unified = untested[0] + untested[1] + untested[2]
    for dom in unified:
        queue.put_nowait(dom)
    with alive_progress.alive_bar(len(unified)) as bar:
        tasks = [asyncio.create_task(bitch(queue, bar),
                                     name='Dom_Worker-{i}') for i in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def main():
    if os.path.exists(avail_file):
        with open(avail_file, "r", encoding='utf8') as raveable:
            domains = set(raveable)
            raveable.close()
    else:
        domains = set()
    untested = await gen_names(domains)
    results = await check_doms(untested)
    for result in results:
        with open(avail_file, 'w', encoding='utf8', newline='\n') as fafa:
            fafa.write(result)
            fafa.write('\n')


if __name__ == '__main__':
    asyncio.run(main())
