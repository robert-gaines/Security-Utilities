#!/usr/bin/env python3

from fpdf import FPDF 

pdf = FPDF(orientation='P',unit='mm',format='A4')

pdf.add_page()

pdf.set_font('Arial', 'B', 16)

pdf.cell(60,30,"This is a test")

pdf.output('test-pdf.pdf','F')


