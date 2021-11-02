#!/bin/bash

make CFG=rel86 clean
make CFG=dbg86 clean
make CFG=rel50 clean
make CFG=dbg50 clean

make CFG=sim5 clean
make CFG=sim5_dbg clean