import requests as rq
import pathlib as pl

bytes = rq.get('https://www.diligent.com/_next/image?url=%2Flogo%2Fdiligent_logo_fullcolor_rgb.svg&w=256&q=75').content
img = pl.Path('img/Diligent_Logo.svg')
img.write_bytes(bytes)

bytes = rq.get('https://qualitydigital.global/wp-content/uploads/2023/04/logo-quality-digital-white.svg').content
img2 = pl.Path('img/Quality_Logo.svg')
img2.write_bytes(bytes)