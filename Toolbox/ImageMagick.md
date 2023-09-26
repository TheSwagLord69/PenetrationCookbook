> ImageMagick, invoked from the command line as magick, is a free and open-source cross-platform software suite for displaying, creating, converting, modifying, and editing raster images.


# Convert

#PDF

Download
```bash
sudo apt install graphicsmagick-imagemagick-compat
```

Create a blank pdf
```bash
convert xc:none -page Letter a.pdf
```
```bash
convert xc:none -page A4 a.pdf
```
```bash
convert xc:none -page 842x595 a.pdf
```