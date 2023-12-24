import pipeline as pl
import streamlit as st
import pandas as pd
from plotly import express as px
import geopandas as gpd
import math


st.set_page_config(page_title="BhuvanRKSHA", page_icon=":shield:")
st.markdown(
    """
            <link rel="stylesheet" media="screen" href="https://fontlibrary.org//face/xolonium" type="text/css">
            <style>
                .st-emotion-cache-10trblm {
                    font-family: 'XoloniumRegular';
                    font-weight: normal;
                    font-style: normal;
                    text-align: center;
                }
            </style>
            """,
    unsafe_allow_html=True,
)

st.title("BhuvanRKSHA")


st.markdown(
    "<div style='text-align: center;'><h5>A tool to detect threats in log files.</h5></div>",
    unsafe_allow_html=True,
)

st.header("Log Threat Detection")

file = st.file_uploader("Upload Log File:", type=["txt"])

st.subheader("OR")

logs = st.text_area(
    "Enter Log Data:",
    height=200,
    value="",
    placeholder="""Paste logs here.
Example:
2023-10-31T06:03:06.283735+05:30 172.26.5.193 logver=506141727 timestamp=1698708792 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:03:12 logid="0000000013"...
                    """,
)
if file is not None:
    logs = file.read().decode("utf-8")

lines = logs.split("\n")
lines[:] = [line for line in lines if line != ""]

if st.button("Run"):
    if lines == []:
        st.write("No logs detected.")
    else:
        df = pd.DataFrame(pl.parse_log(log) for log in lines)
        og = df.copy()
        og = og[~og["dstintfrole"].isna()]
        opog = og.copy()
        df = df.drop(["srcip"], axis=1)
        df = pl.clean_data(df)
        bindf = df.drop(["srcintf", "srcintfrole", "dstintf"], axis=1)
        df = df.drop(["sentpkt"], axis=1)
        binclf = pl.load_model("./models/raksha_v4_0.pkl")
        pred = pl.detect("./models/scaler_v2.pkl",binclf, bindf)
        mltclf = pl.load_classifier("./models/raksha_ultra_xlf.pkl")
        indices = pl.get_threats(pred, lines)
        if indices == []:
            st.write("No threats detected.")
        else:
            st.write(
                "Detected {} threats out of {} logs.".format(sum(pred), len(lines))
            )
            df = pl.classify(mltclf, df, indices)
            threat = pd.DataFrame(data=df + 1, columns=["threat_level"])
            df = dict(pd.Series(df).value_counts())
            og = pd.DataFrame([og.iloc[index] for index in indices])
            og = og.reset_index(drop=True)
            og = pd.concat([og, threat], axis=1)
            for key in df.keys():
                st.write(f"Level {key+1} threats: {df[key]}")
            st.header("Threat Report")
            st.subheader("Threats Found:")
            og[""] = range(1, len(og) + 1)
            og.set_index("", inplace=True)
            l3 = og[og["threat_level"] == 3]
            l2 = og[og["threat_level"] == 2]
            l1 = og[og["threat_level"] == 1]
            st.dataframe(og)
            if not l3.empty:
                st.subheader("Level 3 Threats:")
                st.dataframe(l3)
            if not l2.empty:
                st.subheader("Level 2 Threats:")
                st.dataframe(l2)
            if not l1.empty:
                st.subheader("Level 1 Threats:")
                st.dataframe(l1)

            st.header("Data Visualization")
            st.subheader("Threat Level Distribution")
            col1, col2 = st.columns(2)
            names = list(pd.DataFrame(og["threat_level"].value_counts()).index)
            names = ["Level " + str(i) for i in names]
            data = pd.DataFrame(og["threat_level"].value_counts()).transpose()
            og["threat"] = og["threat_level"].apply(lambda x: "Level " + str(x))
            if len(lines)> 100:
                col1.bar_chart(
                    pd.Series(og["threat"]).value_counts().apply(lambda x: math.log(x)),
                )
            else:
                col1.bar_chart(
                    pd.Series(og["threat"]).value_counts(),
                )
            fig = px.pie(
                values=og["threat_level"].value_counts(),
                names=names,
                height=400,
                width=400,
            )
            col2.plotly_chart(fig)
            st.subheader("Threat Level Distribution by Country")
            opog.srccountry.dropna(inplace=True)
            country_counts = opog["srccountry"].value_counts().reset_index()
            country_counts.columns = ["country", "count"]
            world = px.data.gapminder().query("year==2007")
            world = world.merge(country_counts, on="country", how="left").fillna(0)
            fig = px.choropleth(
                world,
                locations="country",
                locationmode="country names",
                color="count",
                hover_name="country",
                color_continuous_scale="Reds",
            )
            fig.update_geos(
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
            st.plotly_chart(fig)

else:
    st.header("Input Examples")
    st.write(
        "Copy and paste the following examples into the text area above to see how the tool works. You are welcome to mix and match any of the examples below or use your own logs to test the tool."
    )
    st.subheader("Random Log Examples:")
    st.markdown(
        """
                `2023-10-31T06:03:06.283735+05:30 172.26.5.193 logver=506141727 timestamp=1698708792 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:03:12 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698708792 srcip=49.35.192.81 srcport=40584 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstport=443 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943981213 proto=6 action="timeout" policyid=49 policytype="policy" service="HTTPS" dstcountry="Reserved" srccountry="India" trandisp="noop" duration=25 sentbyte=120 rcvdbyte=320 sentpkt=2 rcvdpkt=5 appcat="unscanned" crscore=5 craction=262144 crlevel="low"`

                `2023-10-31T06:03:06.283735+05:30 172.26.5.193 logver=506141727 timestamp=1698708788 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:03:08 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698708788 srcip=49.35.192.81 srcport=40570 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstport=443 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943981076 proto=6 action="timeout" policyid=49 policytype="policy" service="HTTPS" dstcountry="Reserved" srccountry="India" trandisp="noop" duration=25 sentbyte=60 rcvdbyte=320 sentpkt=1 rcvdpkt=5 appcat="unscanned" crscore=5 craction=262144 crlevel="low"`

                `2023-10-31T11:02:35.405983+05:30 172.26.5.193 logver=506141727 timestamp=1698709211 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:11 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709211 srcip=23.22.35.162 srcport=17191 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.66 dstport=443 dstintf="Local_LAN" dstintfrole="undefined" poluuid="eed00e84-e899-51e8-8443-676ac9d33e22" sessionid=1943996156 proto=6 action="client-rst" policyid=67 policytype="policy" service="HTTPS" dstcountry="Reserved" srccountry="United States" trandisp="noop" duration=6 sentbyte=216 rcvdbyte=248 sentpkt=4 appcat="unscanned"`

                `2023-10-31T03:25:39.092502+05:30 172.26.5.193 logver=506141727 timestamp=1698702933 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=03:25:33 logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" eventtime=1698702933 severity="critical" srcip=164.52.0.93 srccountry="Japan" dstip=172.26.2.62 srcintf="LLB- Connect" srcintfrole="wan" dstintf="Local_LAN" dstintfrole="undefined" sessionid=1943784658 action="dropped" proto=6 service="HTTPS" policyid=39 attack="Gh0st.Rat.Botnet" srcport=56067 dstport=443 direction="outgoing" attackid=38503 profile="default" ref="http://www.fortinet.com/ids/VID38503" incidentserialno=1802804642 msg="backdoor: Gh0st.Rat.Botnet," crscore=50 crlevel="critical"`

                `2023-10-31T05:17:00.945220+05:30 172.26.5.193 logver=506141727 timestamp=1698708601 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:00:01 logid="0000000011" type="traffic" subtype="forward" level="warning" eventtime=1698708601 srcip=170.80.110.49 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943972760 proto=1 action="ip-conn" policyid=49 policytype="policy" service="icmp/0/8" appcat="unscanned" crscore=5 craction=262144 crlevel="low"`

                `2023-10-31T05:09:43.880561+05:30 172.26.5.193 logver=506141727 timestamp=1698708407 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=04:56:47 logid="0000000011" type="traffic" subtype="forward" level="warning" eventtime=1698708407 srcip=185.81.113.89 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943966208 proto=1 action="ip-conn" policyid=49 policytype="policy" service="icmp/0/8" appcat="unscanned" crscore=5 craction=262144 crlevel="low"`
                """
    )
    st.subheader("Threat Level 3 Log Examples:")
    st.markdown(
        """
                `2023-10-31T04:45:05.644585+05:30 172.26.5.193 logver=506141727 timestamp=1698707640 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=04:44:00 logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" eventtime=1698707640 severity="high" srcip=211.63.167.125 srccountry="Korea, Republic of" dstip=172.26.2.54 srcintf="LLB- Connect" srcintfrole="wan" dstintf="Local_LAN" dstintfrole="undefined" sessionid=1943942664 action="dropped" proto=6 service="HTTP" policyid=42 attack="HTTP.Unix.Shell.IFS.Remote.Code.Execution" srcport=43529 dstport=443 direction="outgoing" attackid=45677 profile="default" ref="http://www.fortinet.com/ids/VID45677" incidentserialno=1625842232 msg="misc: HTTP.Unix.Shell.IFS.Remote.Code.Execution," crscore=30 crlevel="high"`

                `2023-10-31T03:25:39.092502+05:30 172.26.5.193 logver=506141727 timestamp=1698702933 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=03:25:33 logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" eventtime=1698702933 severity="critical" srcip=164.52.0.93 srccountry="Japan" dstip=172.26.2.62 srcintf="LLB- Connect" srcintfrole="wan" dstintf="Local_LAN" dstintfrole="undefined" sessionid=1943784658 action="dropped" proto=6 service="HTTPS" policyid=39 attack="Gh0st.Rat.Botnet" srcport=56067 dstport=443 direction="outgoing" attackid=38503 profile="default" ref="http://www.fortinet.com/ids/VID38503" incidentserialno=1802804642 msg="backdoor: Gh0st.Rat.Botnet," crscore=50 crlevel="critical"`

                `2023-10-31T03:07:04.076644+05:30 172.26.5.193 logver=506141727 timestamp=1698701810 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=03:06:50 logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" eventtime=1698701810 severity="critical" srcip=164.52.0.93 srccountry="Japan" dstip=172.26.2.57 srcintf="LLB- Connect" srcintfrole="wan" dstintf="Local_LAN" dstintfrole="undefined" sessionid=1943747726 action="dropped" proto=6 service="HTTPS" policyid=34 attack="Gh0st.Rat.Botnet" srcport=48705 dstport=443 direction="outgoing" attackid=38503 profile="default" ref="http://www.fortinet.com/ids/VID38503" incidentserialno=1525791340 msg="backdoor: Gh0st.Rat.Botnet," crscore=50 crlevel="critical"`
                """
    )
    st.subheader("Threat Level 2 Log Examples:")
    st.markdown(
        """
                `2023-10-31T10:52:38.585306+05:30 172.26.5.193 logver=506141727 timestamp=1698709208 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:08 logid="0000000011" type="traffic" subtype="forward" level="warning" eventtime=1698709208 srcip=194.135.25.85 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943993979 proto=1 action="ip-conn" policyid=49 policytype="policy" service="icmp/0/8" appcat="unscanned" crscore=5 craction=262144 crlevel="low"`

                `2023-10-31T05:17:00.945220+05:30 172.26.5.193 logver=506141727 timestamp=1698708601 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:00:01 logid="0000000011" type="traffic" subtype="forward" level="warning" eventtime=1698708601 srcip=170.80.110.49 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943972760 proto=1 action="ip-conn" policyid=49 policytype="policy" service="icmp/0/8" appcat="unscanned" crscore=5 craction=262144 crlevel="low"`

                `2023-10-31T05:09:43.880561+05:30 172.26.5.193 logver=506141727 timestamp=1698708407 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=04:56:47 logid="0000000011" type="traffic" subtype="forward" level="warning" eventtime=1698708407 srcip=185.81.113.89 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943966208 proto=1 action="ip-conn" policyid=49 policytype="policy" service="icmp/0/8" appcat="unscanned" crscore=5 craction=262144 crlevel="low"`
                """
    )
    st.subheader("Threat Level 1 Log Examples:")
    st.markdown(
        """
                `2023-10-31T08:41:54.722524+05:30 172.26.5.193 logver=506141727 timestamp=1698709054 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:07:34 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709054 srcip=172.26.1.200 srcport=57479 srcintf="Local_LAN" srcintfrole="undefined" dstip=8.8.8.8 dstport=53 dstintf="LLB- Connect" dstintfrole="wan" poluuid="69ad58e6-9ef8-51e8-a86a-4e448cabbc0d" sessionid=1943984477 proto=17 action="accept" policyid=52 policytype="policy" service="DNS" dstcountry="United States" srccountry="Reserved" trandisp="noop" duration=180 sentbyte=64 rcvdbyte=123 sentpkt=1 rcvdpkt=1 appcat="unscanned"`

                `2023-10-31T06:16:40.381953+05:30 172.26.5.193 logver=506141727 timestamp=1698708832 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:03:52 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698708832 srcip=172.26.1.200 srcport=54488 srcintf="Local_LAN" srcintfrole="undefined" dstip=8.8.8.8 dstport=53 dstintf="LLB- Connect" dstintfrole="wan" poluuid="69ad58e6-9ef8-51e8-a86a-4e448cabbc0d" sessionid=1943977076 proto=17 action="accept" policyid=52 policytype="policy" service="DNS" dstcountry="United States" srccountry="Reserved" trandisp="noop" duration=180 sentbyte=75 rcvdbyte=91 sentpkt=1 rcvdpkt=1 appcat="unscanned"`

                `2023-10-31T06:13:15.356866+05:30 172.26.5.193 logver=506141727 timestamp=1698708826 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:03:46 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698708826 srcip=172.26.1.200 srcport=61917 srcintf="Local_LAN" srcintfrole="undefined" dstip=8.8.8.8 dstport=53 dstintf="LLB- Connect" dstintfrole="wan" poluuid="69ad58e6-9ef8-51e8-a86a-4e448cabbc0d" sessionid=1943976854 proto=17 action="accept" policyid=52 policytype="policy" service="DNS" dstcountry="United States" srccountry="Reserved" trandisp="noop" duration=180 sentbyte=75 rcvdbyte=91 sentpkt=1 rcvdpkt=1 appcat="unscanned"`
                """
    )
    st.subheader("Safe Log Examples:")
    st.markdown(
        """
                `2023-10-31T11:02:35.405983+05:30 172.26.5.193 logver=506141727 timestamp=1698709215 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:15 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709215 srcip=106.193.78.119 srcport=3082 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.1.176 dstport=990 dstintf="Local_LAN" dstintfrole="undefined" poluuid="ae59ebc2-1562-51e9-555a-fa3846aac163" sessionid=1943996287 proto=6 action="client-rst" policyid=63 policytype="policy" service="FTPS" dstcountry="Reserved" srccountry="India" trandisp="noop" duration=6 sentbyte=124 rcvdbyte=244 sentpkt=3 appcat="unscanned"`
                
                `2023-10-31T11:02:35.405983+05:30 172.26.5.193 logver=506141727 timestamp=1698709214 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:14 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709214 srcip=65.2.1.109 srcport=57934 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstport=443 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943995865 proto=6 action="client-rst" policyid=49 policytype="policy" service="HTTPS" dstcountry="Reserved" srccountry="India" trandisp="noop" duration=19 sentbyte=320 rcvdbyte=2530 sentpkt=6 appcat="unscanned"`
                
                `2023-10-31T11:02:35.405983+05:30 172.26.5.193 logver=506141727 timestamp=1698709211 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:11 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709211 srcip=23.22.35.162 srcport=17191 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.66 dstport=443 dstintf="Local_LAN" dstintfrole="undefined" poluuid="eed00e84-e899-51e8-8443-676ac9d33e22" sessionid=1943996156 proto=6 action="client-rst" policyid=67 policytype="policy" service="HTTPS" dstcountry="Reserved" srccountry="United States" trandisp="noop" duration=6 sentbyte=216 rcvdbyte=248 sentpkt=4 appcat="unscanned"`
                
                `2023-10-31T11:02:35.405983+05:30 172.26.5.193 logver=506141727 timestamp=1698709215 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:15 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709215 srcip=115.97.144.48 srcport=52867 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.65 dstport=443 dstintf="Local_LAN" dstintfrole="undefined" poluuid="d92146b0-099c-51e9-d9b2-142b72ef82b7" sessionid=1943996365 proto=6 action="close" policyid=60 policytype="policy" service="HTTPS" dstcountry="Reserved" srccountry="India" trandisp="noop" duration=3 sentbyte=416 rcvdbyte=9096 sentpkt=9 rcvdpkt=13 appcat="unscanned"`
                
                `2023-10-31T10:52:38.585306+05:30 172.26.5.193 logver=506141727 timestamp=1698709208 tz="UTC+5:30" devname="FGT3600C_HA" devid="FG3K6C3A15800081" vd="root" date=2023-10-31 time=05:10:08 logid="0000000013" type="traffic" subtype="forward" level="notice" eventtime=1698709208 srcip=194.135.25.85 srcintf="LLB- Connect" srcintfrole="wan" dstip=172.26.2.51 dstintf="Local_LAN" dstintfrole="undefined" poluuid="3367bf4c-74ff-51e8-3e96-72b0684b3e81" sessionid=1943993979 proto=1 action="accept" policyid=49 policytype="policy" service="PING" dstcountry="Reserved" srccountry="United Kingdom" trandisp="noop" duration=70 sentbyte=132 rcvdbyte=172 sentpkt=3 rcvdpkt=3 appcat="unscanned"`
                """
    )
