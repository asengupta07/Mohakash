import sys
import threading
import time
from itertools import islice
import pandas as pd
import pipeline as pl
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph
import plotly.graph_objects as go
import plotly.express as px
import math
import smtplib, ssl, csv, random
from email.message import EmailMessage
import time
from zipfile import ZipFile
import os
import random

replyto = 'jaceknight104@gmail.com'
subject = 'REPORT'
name = 'BhuvanRKSHA'

counter = {}
reboot_time = 3000 

with open("user.csv") as f:
    data = [row for row in csv.reader(f)]

file_list = ['assets/email.txt']


def write(src, dst, t):
    with open(src, "r") as sf:
        lines = sf.readlines()
    i = 0
    while i < len(lines):
        with open(dst, "a") as df:
            df.write(lines[i])
        i += 1
        time.sleep(t)


def read(src, pos, n):
    i = 0
    while True:
        with open(src, "r") as file:
            file.seek(pos)
            new = list(islice(file, n))
            if len(new) >= n:
                i+=1
                lines = new[:n]
                lines = [line.strip() for line in lines]
                lines[:] = [line for line in lines if line != ""]
                df = pd.DataFrame(pl.parse_log(log) for log in lines)
                og = df.copy()
                og = og[~og["dstintfrole"].isna()]
                opog = og.copy()
                df = df.drop(["srcip"], axis=1)
                df = pl.clean_data(df)
                bindf = df.drop(["srcintf", "srcintfrole", "dstintf"], axis=1)
                df = df.drop(["sentpkt"], axis=1)
                binclf = pl.load_model("./models/raksha_v5_2.pkl")
                pred = pl.detect("./models/scaler_v3.pkl", binclf, bindf)
                mltclf = pl.load_classifier("./models/raksha_ultra_xlf.pkl")
                indices = pl.get_threats(pred, lines)
                if indices == []:
                    print("No threats detected")
                else:
                    print(
                        "Detected {} threats out of {} logs.".format(sum(pred), len(lines))
                    )
                    df = pl.classify(mltclf, df, indices)
                    t = df
                    threat = pd.DataFrame(data=df + 1, columns=["threat_level"])
                    df = dict(pd.Series(df).value_counts())
                    og = pd.DataFrame([og.iloc[index] for index in indices])
                    og = og.reset_index(drop=True)
                    og = pd.concat([og, threat], axis=1)
                    for key in df.keys():
                        print(f"Level {key+1} threats: {df[key]}")
                    og[""] = range(1, len(og) + 1)
                    og.set_index("", inplace=True)
                    pdf_path = f"reports/report{i}.pdf"
                    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
                    style = getSampleStyleSheet()["Heading1"]
                    title = Paragraph("BhuvanRKSHA Report", style)
                    style = getSampleStyleSheet()["BodyText"]
                    brief = Paragraph(
                        "Detected {} threats out of {} logs.".format(sum(pred), len(lines)),
                        style,
                    )
                    report = [title, brief]
                    for key in df.keys():
                        style = getSampleStyleSheet()["BodyText"]
                        body = Paragraph(
                            f"Level {key+1} threats: {df[key]}", style
                        )
                        report.append(body)
                    body = Paragraph(
                        "The following report contains the level 3 threats (if any) detected by BhuvanRKSHA.",
                        style,
                    )
                    report.append(body)
                    if 2 in t:
                        style = getSampleStyleSheet()["Heading2"]
                        subtitle = Paragraph("Level 3 Threats", style)
                        report.append(subtitle)
                        for x, k in enumerate(t+1):
                            if k == 3:
                                style = getSampleStyleSheet()["BodyText"]
                                body = Paragraph(lines[x], style)
                                report.append(body)
                    # style = getSampleStyleSheet()["Heading2"]
                    # subtitle = Paragraph("Level 2 Threats", style)
                    # report.append(subtitle)
                    # for x, k in enumerate(t+1):
                    #     if k == 2:
                    #         style = getSampleStyleSheet()["BodyText"]
                    #         body = Paragraph(lines[x], style)
                    #         report.append(body)
                    # style = getSampleStyleSheet()["Heading2"]
                    # subtitle = Paragraph("Level 1 Threats", style)
                    # report.append(subtitle)
                    # for x, k in enumerate(t+1):
                    #     if k == 1:
                    #         style = getSampleStyleSheet()["BodyText"]
                    #         body = Paragraph(lines[x], style)
                    #         report.append(body)
                    doc.build(report)
                    names = list(pd.DataFrame(og["threat_level"].value_counts()).index)
                    names = ["Level " + str(i) for i in names]
                    og["threat"] = og["threat_level"].apply(lambda x: "Level " + str(x))
                    if i == 3:
                        print("here")
                    pdf_path = f"reports/visual_report{i}.pdf"
                    if i == 3:
                        print("here again")
                    c = canvas.Canvas(pdf_path, pagesize=letter)
                    c.setFont("Helvetica-Bold", 16)
                    c.drawString(50, 750, "Threat Level Distribution")
                    col1_x, col2_x = 50, 300
                    col1_y, col2_y = 500, 500
                    fig1 = go.Figure()
                    fig1.add_trace(go.Bar(
                        x=pd.Series(og["threat"]).value_counts().index,
                        y=pd.Series(og["threat"]).value_counts().apply(lambda x: math.log(x)) if len(lines) > 100 else pd.Series(og["threat"]).value_counts(),
                        marker_color='skyblue',
                        text=pd.Series(og["threat"]).value_counts(),  # Display count above each bar
                        textposition='auto',
                    ))
                    if i == 3:
                        print("here again2")
                    fig1.update_layout(xaxis_title="Threat Level", yaxis_title="Count (log scale)" if len(lines) > 100 else "Count")
                    fig2 = px.pie(
                        values=og["threat_level"].value_counts(),
                        names=["Level " + str(i) for i in pd.DataFrame(og["threat_level"].value_counts()).index],
                        height=400,
                        width=400,
                    )
                    c.setFont("Helvetica-Bold", 16)
                    c.drawString(50, 450, "Threat Level Distribution by Country")

                    col3_x, col3_y = 50, 50
                    country_counts = opog["srccountry"].value_counts().reset_index()
                    country_counts.columns = ["country", "count"]
                    world = px.data.gapminder().query("year==2007")
                    world = world.merge(country_counts, on="country", how="left").fillna(0)
                    fig3 = px.choropleth(
                        world,
                        locations="country",
                        locationmode="country names",
                        color="count",
                        hover_name="country",
                        color_continuous_scale="Reds",
                    )
                    fig3.update_geos(
                        resolution=110,
                        showcoastlines=True,
                        coastlinecolor="black",
                        showland=True,
                        landcolor="black",
                        showocean=True,
                        oceancolor="lightblue",
                        showlakes=True,
                        lakecolor="white",
                    )
                    if i == 3:
                        print("here again3")
                    image1_path = "buffer/chart1.png"
                    fig1.write_image(image1_path)

                    image2_path = "buffer/chart2.png"
                    fig2.write_image(image2_path)

                    image3_path = "buffer/chart3.png"
                    fig3.write_image(image3_path)
                    if i == 3:
                        print("here again4")
                    c.drawInlineImage(image1_path, col1_x, col1_y, width=250, height=200)
                    c.drawInlineImage(image2_path, col2_x, col2_y, width=250, height=200)
                    c.drawInlineImage(image3_path, col3_x, col3_y, width=500, height=400)
                    c.save()
                    if i == 3:
                        print("here again5")
                        with open('mails.csv', 'r') as csvfile:
                            datareader = csv.reader(csvfile)
                            for row in datareader:
                                random_user = random.choice(data)
                                sender = random_user[0]
                                password = random_user[1]
                                
                                if sender not in counter:
                                    counter[sender] = 0
                                
                                if counter[sender] >= 500:
                                    print(f"Email limit reached for {sender}. Rebooting for {reboot_time} seconds.")
                                    time.sleep(reboot_time)
                                    counter[sender] = 0 
                                
                                try:
                                    context = ssl.create_default_context()
                                    server = smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context)
                                    server.login(sender, password)
                                    em = EmailMessage()
                                    em['from'] = f'{name} <{sender}>'
                                    em['Reply-To'] = replyto
                                    em['To'] = row
                                    em['subject'] = subject
                                    random_file = random.choice(file_list)
                                    with open(random_file, 'r') as file:
                                        html_msg = file.read()
                                    em.add_alternative(html_msg, subtype='html')
                                    zip_filename = 'report.zip'
                                    with ZipFile(zip_filename, 'w') as zipf:
                                        for root, _, files in os.walk("reports"):
                                            for file in files:
                                                file_path = os.path.join(root, file)
                                                zipf.write(file_path, os.path.relpath(file_path, "reports"))
                                    with open(zip_filename, 'rb') as attachment:
                                        em.add_attachment(attachment.read(), maintype='application', subtype='zip', filename='report.zip')
                                    server.send_message(em)
                                    counter[sender] += 1
                                    print(counter[sender], " emails sent", "From ", sender, "To ", row, "File ", random_file)
                                    
                                    time.sleep(0.1)
                                    
                                except Exception as e:
                                    print(f"Error sending email From {sender} to {row}:", e)

                                server.close()
                l = 0
                for line in lines:
                    l += len(line)
                pos += l
        time.sleep(1)


file = sys.argv[1]
source = sys.argv[2]

wthread = threading.Thread(target=write, args=(source, file, 0.00001))

# wthread.start()

with open(file, "r") as init:
    pos = init.tell()

rthread = threading.Thread(target=read, args=(file, pos, 100000))


wthread.start()
rthread.start()

wthread.join()
rthread.join()
