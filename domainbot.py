from asyncio.tasks import as_completed, create_task
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


async def write_to(result):
    with open(avail_file, 'a', encoding='utf8', newline='\n') as wf:
        wf.write(result)
        wf.write('\n')
    return True


# Function to check the availability of a domain name
@retry(exceptions=whois.WhoisCommandTimeout, tries=5, delay=3, jitter=(3, 5))
@retry(exceptions=whois.WhoisQuotaExceeded, tries=5, delay=5, backoff=5, jitter=(1, 3))
async def bitch(queue, bar):
    # Lock process in a loop until it is canceled.
    while True:
        dom = await queue.get()
        save = False
        up_prgs = False
        try:
            reg = whois.query(dom, withPublicSuffix=True)
            if reg:
                up_prgs = True
        except whois.WhoisCommandTimeout:
            up_prgs = True
            raise Exception('Timeout Occurred')
        except whois.WhoisPrivateRegistry:
            up_prgs = True
        except whois.WhoisQuotaExceeded:
            up_prgs = True
            raise Exception('Quota Exceeded')
        except WhoisException:
            save = True
        if save:
            writ = await write_to(dom)
            if writ:
                bar()
                queue.task_done()
        if up_prgs:
            bar()
            queue.task_done()


async def task_cancel(other_task):
    await asyncio.sleep(0.3)
    other_task.cancel()


async def check_doms(untested):
    unified = untested[0] + untested[1] + untested[2]
    queue = asyncio.Queue()
    with alive_progress.alive_bar(len(unified)) as bar:
        for i in unified:
            queue.put_nowait(i)
        tasks = []
        for i in range(10):
            name = str(f'bitch-{i}')
            task = asyncio.create_task(bitch(queue, bar), name=name)
            twait = await asyncio.wait_for(task, timeout=3)
            tcan = asyncio.create_task(task_cancel(twait))
            wtask = asyncio.create_task(tcan)
            tasks.append(wtask)
        qcomp = asyncio.create_task(queue.join())
        await asyncio.wait([qcomp, *tasks])
        if not qcomp.done():
            for t in tasks:
                if t.done():
                    t.result()
        await asyncio.gather(*tasks, return_exceptions=True)
        for task in tasks:
            task.cancel()
        return True


async def main():
    if os.path.exists(avail_file):
        with open(avail_file, "r", encoding='utf8') as raveable:
            domains = set(raveable)
            raveable.close()
    else:
        domains = set()
    untested = await gen_names(domains)
    completed = await check_doms(untested)
    if completed:
        print('Done!')


if __name__ == '__main__':
    asyncio.run(main())
