import sys, io
from PIL import Image, ImageDraw
out = sys.argv[1]
img = Image.new("RGB", (333, 211))
d = ImageDraw.Draw(img)
for i in range(0, 333, 7):
    d.line([(i, 0), (333 - i, 211)], fill=(i % 256, (i * 3) % 256, (i * 7) % 256), width=3)
d.ellipse([40, 30, 200, 180], fill=(200, 40, 90))
exif = Image.Exif()
exif[0x0112] = 6
exif[0x010F] = "Camera Maker"
exif[0x0110] = "Model X"
gps = {1: "N", 2: (51.0, 30.0, 0.0), 3: "W", 4: (0.0, 7.0, 0.0)}
exif[0x8825] = gps
img.save(f"{out}/exif420.jpg", quality=85, exif=exif.tobytes(), comment=b"secret comment")
img.save(f"{out}/q444.jpg", quality=92, subsampling=0)
img.convert("L").save(f"{out}/gray.jpg", quality=80)
img.save(f"{out}/prog.jpg", quality=80, progressive=True, exif=exif.tobytes())
try:
    img.save(f"{out}/rst.jpg", quality=80, restart_marker_blocks=3)
except TypeError as e:
    print("no restart", e)
img.save(f"{out}/opt.jpg", quality=75, optimize=True)
from PIL import PngImagePlugin
info = PngImagePlugin.PngInfo(); info.add_text("Comment", "secret"); info.add_itxt("XML:com.adobe.xmp", "<x/>")
img.save(f"{out}/text.png", pnginfo=info)
img.convert("P").save(f"{out}/pal.gif", comment=b"secret")
frames = [img.rotate(a) for a in (0, 30, 60)]
frames[0].save(f"{out}/anim.gif", save_all=True, append_images=frames[1:], loop=0, duration=100)
