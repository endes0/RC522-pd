##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2010-2014 Uwe Hermann <uwe@hermann-uwe.de>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd



class Decoder(srd.Decoder):
    api_version = 3
    id = 'rc522'
    name = 'rc522'
    longname = 'rc522'
    desc = 'Mifare MRC522 NFC protocol.'
    license = 'gplv2+'
    inputs = ['i2c']
    outputs = []
    tags = ['Sensor']
    annotations = \
    (
        ('p0', 'P0: Command and status'),
        ('p1', 'P1: Command'),
        ('p2', 'P2: Configuration'),
        ('p3', 'P3: Test register'),
        ('p0W', 'P0: Command and status'),
        ('p1w', 'P1: Command'),
        ('p2w', 'P2: Configuration'),
        ('p3w', 'P3: Test register'),
        ('summary', 'Summary'),
        ('warnings', 'Warnings'),
    )
    annotation_rows = (
        ('wregs', 'Write Registers', tuple(range(4))),
        ('rregs', 'Read Registers', tuple(range(4, 8))),
        ('summary', 'Summary', (8,)),
        ('warnings', 'Warnings', (9,)),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.state = 'IDLE'
        self.reg = 0x00
        self.ss = self.es = self.ss_block = self.es_block = 0
        self.writebuf = []
        self.readbuf = []
        self.read_reg_offset = 4

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def putx(self, data):
        self.put(self.ss, self.es, self.out_ann, data)

    def putb(self, data):
        self.put(self.ss_block, self.es_block, self.out_ann, data)

    def putregb(self, name, page, data, isread):
        offset = 0
        if isread:
            offset = self.read_reg_offset
        self.putb([page + offset, [f"{data}: 0x{data:02X}"]])

    # PAGE 0

    def handle_reg_0x01(self, databyte, read):
        self.putregb("CommandReg", 0, databyte, read)

    def handle_reg_0x02(self, databyte, read):
        self.putregb("ComIEnReg", 0, databyte, read)
    
    def handle_reg_0x03(self, databyte, read):
        self.putregb("DivIEnReg", 0, databyte, read)
    
    def handle_reg_0x04(self, databyte, read):
        self.putregb("ComIrqReg", 0, databyte, read)

    def handle_reg_0x05(self, databyte, read):
        self.putregb("DivIrqReg", 0, databyte, read)
    
    def handle_reg_0x06(self, databyte, read):
        self.putregb("ErrorReg", 0, databyte, read)
    
    def handle_reg_0x07(self, databyte, read):
        self.putregb("Status1Reg", 0, databyte, read)

    def handle_reg_0x08(self, databyte, read):
        self.putregb("Status2Reg", 0, databyte, read)

    def handle_reg_0x09(self, databyte, read):
        self.putregb("FIFODataReg", 0, databyte, read)

    def handle_reg_0x0A(self, databyte, read):
        self.putregb("FIFOLevelReg", 0, databyte, read)
    
    def handle_reg_0x0B(self, databyte, read):
        self.putregb("WaterLevelReg", 0, databyte, read)

    def handle_reg_0x0C(self, databyte, read):
        self.putregb("ControlReg", 0, databyte, read)
    
    def handle_reg_0x0D(self, databyte, read):
        self.putregb("BitFramingReg", 0, databyte, read)
    
    def handle_reg_0x0E(self, databyte, read):
        self.putregb("CollReg", 0, databyte, read)

    # PAGE 1

    def handle_reg_0x11(self, databyte, read):
        self.putregb("ModeReg", 1, databyte, read)

    def handle_reg_0x12(self, databyte, read):
        self.putregb("TxModeReg", 1, databyte, read)
    
    def handle_reg_0x13(self, databyte, read):
        self.putregb("RxModeReg", 1, databyte, read)
    
    def handle_reg_0x14(self, databyte, read):
        self.putregb("TxControlReg", 1, databyte, read)

    def handle_reg_0x15(self, databyte, read):
        self.putregb("TxASKReg", 1, databyte, read)

    def handle_reg_0x16(self, databyte, read):
        self.putregb("TxSelReg", 1, databyte, read)

    def handle_reg_0x17(self, databyte, read):
        self.putregb("RxSelReg", 1, databyte, read)

    def handle_reg_0x18(self, databyte, read):
        self.putregb("RxThresholdReg", 1, databyte, read)

    def handle_reg_0x19(self, databyte, read):
        self.putregb("DemodReg", 1, databyte, read)
    
    def handle_reg_0x1C(self, databyte, read):
        self.putregb("MfTxReg", 1, databyte, read)

    def handle_reg_0x1D(self, databyte, read):
        self.putregb("MfRxReg", 1, databyte, read)

    def handle_reg_0x1F(self, databyte, read):
        self.putregb("SerialSpeedReg", 1, databyte, read)
    
    # PAGE 2
    def handle_reg_0x21(self, databyte, read):
        self.putregb("CRCResultRegM", 2, databyte, read)
    
    def handle_reg_0x22(self, databyte, read):
        self.putregb("CRCResultRegL", 2, databyte, read)

    def handle_reg_0x23(self, databyte, read):
        self.putregb("ModWidthReg", 2, databyte, read)

    def handle_reg_write(self, databyte):
        if len(self.writebuf) < 2:
            self.writebuf.append(databyte)

    def decode(self, ss, es, data):
        cmd, databyte = data

        # Collect the 'BITS' packet, then return. The next packet is
        # guaranteed to belong to these bits we just stored.
        if cmd == 'BITS':
            self.bits = databyte
            return

        self.ss, self.es = ss, es

        # State machine.
        if self.state == 'IDLE':
            # Wait for an I²C START condition.
            if cmd != 'START':
                return
            self.state = 'GET SLAVE ADDR'
            self.ss_block = ss
        elif self.state == 'GET SLAVE ADDR':
            # Wait for an address read/write operation.
            if cmd == 'ADDRESS READ':
                self.state = 'READ REGS'
            elif cmd == 'ADDRESS WRITE':
                self.state = 'WRITE REGS'
        elif self.state == 'READ REGS':
            if cmd == 'DATA READ':
                self.readbuf.append(databyte)
            elif cmd == 'STOP':
                self.es_block = es

                #check if attr exists
                if hasattr(self, 'handle_reg_0x%02X' % self.reg):
                    handle_reg = getattr(self, 'handle_reg_0x%02X' % self.reg)
                    handle_reg(self.readbuf[0], True)
                else:
                    self.putb([9, ['Ignoring read to: %02X' % self.reg]])

                self.readbuf = []
                self.state = 'IDLE'
            else:
                # self.putx([14, ['Ignoring: %s (data=%s)' % (cmd, databyte)]])
                pass
        elif self.state == 'WRITE REGS':
            if cmd == 'DATA WRITE':
                self.handle_reg_write(databyte)
            elif cmd == 'STOP' or cmd == 'START REPEAT':
                self.es_block = es
                #self.output_init_seq()
                
                if len(self.writebuf) > 0:
                    self.reg = self.writebuf[0]

                if len(self.writebuf) == 2:
                    #check if attr exists
                    if hasattr(self, 'handle_reg_0x%02X' % self.reg):
                        handle_reg = getattr(self, 'handle_reg_0x%02X' % self.reg)
                        handle_reg(self.writebuf[1], False)
                    else:
                        self.putb([9, ['Ignoring write to: %02X' % self.reg]])
                elif len(self.writebuf) > 2 or len(self.writebuf) == 0:
                    self.putb([9, ['Ignoring write: %s' % self.writebuf]])


                self.writebuf = []
                self.state = 'IDLE'
                if cmd == 'START REPEAT':
                    self.state = 'GET SLAVE ADDR'
            else:
                #self.putx([14, ['Ignoring: %s (data=%s)' % (cmd, databyte)]])
                pass
