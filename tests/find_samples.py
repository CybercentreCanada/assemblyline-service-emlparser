#!/bin/env python
import os
import random
from datetime import datetime

import extract_msg
import toml
import vt

vt_key = toml.load(os.path.expanduser("~/.vt.toml"))["apikey"]

with vt.Client(vt_key) as vtclient:
    for _ in range(1000):
        rand_date = datetime(
            2022, random.randint(1, 12), random.randint(1, 28), random.randint(0, 23), random.randint(0, 59)
        )
        query = f'type:outlook AND ls:"{rand_date.isoformat()}-"'
        it = vtclient.iterator("/intelligence/search", params={"query": query}, limit=25)
        for obj in it:
            print(f"Testing {obj.id}")
            with open(obj.id, "wb") as f:
                vtclient.download_file(obj.id, f)

            try:
                msg = extract_msg.openMsg(obj.id)
            except Exception:
                print("openMsg exception")
                os.remove(obj.id)
                continue

            for attachment in msg.attachments:
                isinstance(attachment, extract_msg.signed_attachment.SignedAttachment)

            os.remove(obj.id)
