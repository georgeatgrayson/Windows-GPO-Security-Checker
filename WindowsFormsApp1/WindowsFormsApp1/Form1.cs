using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.DirectoryServices;
using Microsoft.GroupPolicy;
using System.Xml;
using System.Diagnostics;
using System.Reflection;
using Microsoft.Win32;
using System.Collections.ObjectModel;

namespace WindowsFormsApp1
{

    public partial class Form1 : Form
    {
        private int state = 0;
        public int page = 0;
        public int section = 0;
        private int maxPage = 0;
        private string path = "";
        public Gpo gpo;
        public GpoBackup gpb;
        private Dictionary<string, int> Policies = new Dictionary<string, int>();
        

        public List<PolicySection> Pols = new List<PolicySection>();

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            var os = Environment.OSVersion;
            if (os.Version.Major < 6 || os.Version.Major == 6 && os.Version.Minor == 0)                 //Checks OS for up-to-date/outdated
            {
                MessageBox.Show("Your version of windows is unsupported by miscrosoft and completely vulnerable. Any attempt to secure this device with the current operating system is meaningless as the operating system will remain vulnerable. You should update this to the latest version of Windows Server as soon as possible.");
                this.Close();
            }else if(os.Version.Major == 6)
            {
                MessageBox.Show("You do not appear to have the latest version of windows. You are recommended to upgrade to the latest version, as newer versions generally have fewer vulnerabilities and better overall security features. Certain policies that are recommended will be unavailable to you.");
            }


        }

        private void NextButton_Click(object sender, EventArgs e)
        {
            if (state == 0)
            {
                //Gets GP XML

                var guid = new Guid("31B2F340-016D-11D2-945F-00C04FB984F9");
                var domain = new GPDomain(System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName);
                gpo = domain.GetGpo(guid);
                var gpoReport = gpo.GenerateReport(ReportType.Xml);
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(gpoReport);

                //Parses GP XML

                List<XmlNode> extensionData = new List<XmlNode>();
                XmlNode extIter = GetChildByName(GetChildByName(doc.LastChild, "Computer"), "ExtensionData");
                while (extIter != null)
                {
                    if (extIter.Name == "ExtensionData")
                    {
                        extensionData.Add(extIter);
                    }
                    extIter = extIter.NextSibling;
                }
                
                extIter = GetChildByName(GetChildByName(doc.LastChild, "User"), "ExtensionData");
                while (extIter != null)
                {
                    if (extIter.Name == "ExtensionData")
                    {
                        extensionData.Add(extIter);
                    }
                    extIter = extIter.NextSibling;
                }
                
                var i = 2;
                foreach (XmlNode data in extensionData)
                {
                    XmlNode extensions = data.FirstChild;
                    if (data == extensionData[0])
                    {
                        foreach (XmlNode pol in extensions)
                        {
                            if (pol.Name == "q1:Account")
                            {
                                var name = GetChildByName(pol, "q1:Name");
                                var num = GetChildByName(pol, "q1:SettingNumber");
                                var tf = GetChildByName(pol, "q1:SettingBoolean");
                                if (name != null && num != null)
                                {
                                    Policies.Add(pol.ChildNodes[0].InnerText, Int32.Parse(pol.ChildNodes[1].InnerText));
                                }
                                if (name != null && tf != null)
                                {
                                    if (tf.InnerText == "true")
                                    {
                                        Policies.Add(pol.ChildNodes[0].InnerText, 1);
                                    }
                                    else
                                    {
                                        Policies.Add(pol.ChildNodes[0].InnerText, 0);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        if (GetChildByName(data, "Name")!=null&& GetChildByName(data, "Name").InnerText== "Windows Firewall")
                        {
                            //Special case as the firewall is displayed differently

                            foreach (XmlNode pol in extensions)
                            {
                                if (pol.Name == "q" + i + ":DomainProfile")
                                {
                                    var lpm = GetChildByName(pol, "q"+i+":AllowLocalPolicyMerge");
                                    var lpmState = (lpm == null) ? 2 : (lpm.InnerText == "true") ? 1 : 0;
                                    Policies.Add("Domain Profile - Apply local firewall rules", lpmState);
                                    var efw = GetChildByName(pol, "q" + i + ":EnableFirewall");
                                    var efwState = (efw == null) ? 2 : (efw.InnerText == "true") ? 1 : 0;
                                    Policies.Add("Domain Profile", efwState);
                                    //var ibc = GetChildByName(pol, "q5:DefaultInboundAction");
                                    //var ibcState = (ibc == null) ? 0 : (ibc.InnerText=="true")?1:0;
                                    //var obc = GetChildByName(pol, "q5:DefaultOutboundAction");
                                    //var obcState = (obc == null) ? 0 : (obc.InnerText == "true") ? 1 : 0;
                                }
                                else if (pol.Name == "q" + i + ":PrivateProfile")
                                {
                                    var lpm = GetChildByName(pol, "q" + i + ":AllowLocalPolicyMerge");
                                    var lpmState = (lpm == null) ? 2 : (lpm.InnerText == "true") ? 1 : 0;
                                    Policies.Add("Private Profile - Apply local firewall rules", lpmState);
                                    var efw = GetChildByName(pol, "q" + i + ":EnableFirewall");
                                    var efwState = (efw == null) ? 2 : (efw.InnerText == "true") ? 1 : 0;
                                    Policies.Add("Private Profile", efwState);
                                }
                                else if (pol.Name == "q5:PublicProfile")
                                {
                                    var lpm = GetChildByName(pol, "q" + i + ":AllowLocalPolicyMerge");
                                    var lpmState = (lpm == null) ? 2 : (lpm.InnerText == "true") ? 1 : 0;
                                    Policies.Add("Public Profile - Apply local firewall rules", lpmState);
                                    var efw = GetChildByName(pol, "q" + i + ":EnableFirewall");
                                    var efwState = (efw == null) ? 2 : (efw.InnerText == "true") ? 1 : 0;
                                    Policies.Add("Public Profile", efwState);

                                }
                            }
                        }
                        else { 
                            foreach (XmlNode pol in extensions)
                            {
                                if (pol.Name == "q"+i.ToString()+":Policy")
                                {

                                    //Parses enabled/disabled/not configured to numbers

                                    var name = GetChildByName(pol, "q" + i.ToString()+":Name");
                                    var state = GetChildByName(pol, "q" + i.ToString()+":State");
                                    if (name != null && state != null)
                                    {
                                        if (state.InnerText == "Enabled")
                                        {
                                            Policies.Add(pol.ChildNodes[0].InnerText, 1);
                                        }
                                        else if (state.InnerText == "Disabled")
                                        {
                                            Policies.Add(pol.ChildNodes[0].InnerText, 0);
                                        }
                                        else
                                        {
                                            Policies.Add(pol.ChildNodes[0].InnerText, 2);
                                        }
                                    }
                                }
                            }
                        }
                        i++;
                    }
                }

                //Parses PoliciesXML to the dictionary to generate the pages

                XmlDocument policies = new XmlDocument();
                Assembly assembly = Assembly.GetExecutingAssembly();
                var a = assembly.GetManifestResourceNames();
                Stream stream = assembly.GetManifestResourceStream("WindowsFormsApp1.PoliciesXML.xml");
                policies.Load(stream);

                XmlNode p = policies.ChildNodes[1].ChildNodes[0];

                while (p!=null)
                {
                    if (p.NodeType.ToString() == "Element") { 
                        Pols.Add(new PolicySection(p));
                    }
                    p = p.NextSibling;
                }

                //Configure first page

                state = 1;
                GuidanceButton.Visible = true;
                MarkAsDone.Visible = true;
                NextButton.Text = "Next >>";
                this.Text = Pols[section].name;
            }
            //If within pages
            if (state == 1)
            {
                if (!Pols[section].isPolicyAt(page-1)&&page!=0&&section==Pols.Count-1)
                {

                    //Exit to finish page

                    InfoBox.Text = "";
                    state = 2;
                    PrevButton.Visible = false;
                    GuidanceButton.Visible = false;
                    MarkAsDone.Visible = false;
                    NameLabel.Text = "";
                    NextButton.Text = "Finish";
                }
                else
                {
                    if (!Pols[section].isPolicyAt(page - 1) && page != 0)
                    {
                        //Change section

                        section += 1;
                        this.Text = Pols[section].name;
                        page = 0;
                    }
                    if (page == 0)
                    {
                        //Display header page for page 0

                        NameLabel.Text = "";
                        InfoBox.Text = Pols[section].headerText(Policies);
                        if (Pols[section].isSafe())
                        {
                            SkipButton.Visible = true;
                        }
                        else
                        {

                            SkipButton.Visible = false;
                        }
                        GuidanceButton.Visible = false;
                        page += 1;
                        MarkAsDone.Visible = false;
                    }
                    else
                    {
                        //Display individual policy page

                        SkipButton.Visible = false;
                        var currentPolicy = Pols[section].policyAt(page - 1);
                        var name = currentPolicy.getName();
                        NameLabel.Text = name;
                        InfoBox.Height = 329 - NameLabel.Height;             //Avoids height overflow on name
                        InfoBox.Top = 18 + NameLabel.Height;
                        if (Policies.ContainsKey(name))
                        {
                            //Use setting found
                            InfoBox.Text = currentPolicy.check(Policies[name]).Trim();
                            NameLabel.ForeColor = (currentPolicy.isRecommended(Policies[name])) ? currentPolicy.recColour() : currentPolicy.nonRecColour();
                        }
                        else
                        {
                            //Otherwise use default
                            InfoBox.Text = currentPolicy.useDefault().Trim();
                            NameLabel.ForeColor = (currentPolicy.isRecommended(-1)) ? currentPolicy.recColour() : currentPolicy.nonRecColour();
                        }
                        if (currentPolicy.guidance() == "")
                        {
                            GuidanceButton.Visible = false;
                        }
                        else
                        {
                            GuidanceButton.Visible = true;
                        }
                    
                        page += 1;
                        PrevButton.Visible = true;
                        MarkAsDone.Visible = true;
                        //Very last page show finish instead of next
                        if (!Pols[section].isPolicyAt(page-1) && section == Pols.Count - 1)
                        {
                            NextButton.Text = "Finish";
                            MarkAsDone.Visible = false;
                        }
                    }
                }
            }
            else
            {
                this.Close();
            }

        }

        private void PrevButton_Click(object sender, EventArgs e)
        {
            if (state == 1)
            {
                if (page == 1)
                {
                    //Go back a section

                    section -= 1;
                    this.Text = Pols[section].name;
                    page = Pols[section].size;
                    NameLabel.Text = "";
                }
                else { 
                    page -= 2;
                }
                if (page == 0)
                {
                    //Set header page
                    InfoBox.Text = Pols[section].headerText(Policies);
                    if (Pols[section].isSafe())
                    {
                        SkipButton.Visible = true;
                    }
                    else
                    {

                        SkipButton.Visible = false;
                    }
                    GuidanceButton.Visible = false;
                    page += 1;
                    if (section == 0) PrevButton.Visible = false;
                    MarkAsDone.Visible = false;
                    NameLabel.Text = "";
                }
                else
                {
                    //Go back a page
                    SkipButton.Visible = false;
                    var currentPolicy = Pols[section].policyAt(page - 1);
                    var name = currentPolicy.getName();
                    NameLabel.Text = name;
                    InfoBox.Height = 329 - NameLabel.Height;
                    InfoBox.Top = 18 + NameLabel.Height;
                    if (Policies.ContainsKey(name))
                    {
                        InfoBox.Text = currentPolicy.check(Policies[name]).Trim();
                        NameLabel.ForeColor = (currentPolicy.isRecommended(Policies[name])) ? currentPolicy.recColour() : currentPolicy.nonRecColour();
                    }
                    else
                    {
                        InfoBox.Text = currentPolicy.useDefault().Trim();
                        NameLabel.ForeColor = (currentPolicy.isRecommended(-1)) ? currentPolicy.recColour() : currentPolicy.nonRecColour();
                    }
                    if (currentPolicy.guidance() == "")
                    {
                        GuidanceButton.Visible = false;
                    }
                    else
                    {
                        GuidanceButton.Visible = true;
                    }

                    page += 1;
                    NextButton.Text = "Next >>";
                    
                    MarkAsDone.Visible = true;
                }
            }
        }

        private void MarkAsDone_CheckedChanged(object sender, EventArgs e)
        {
            //Remove the current page and move the the next
            var confirmResult = MessageBox.Show("This will remove this page. Only do this if you are satisfied with your choices for this policy. Continue?", "Confirm done", MessageBoxButtons.OKCancel);
            if (confirmResult == DialogResult.OK)
            {
                
                var name = Pols[section].policyAt(page-1).getName();
                NameLabel.Text = name;
                if (Policies.ContainsKey(name))
                {
                    InfoBox.Text = Pols[section].policyAt(page - 1).check(Policies[name]).Trim();
                }
                else
                {
                    InfoBox.Text = Pols[section].policyAt(page - 1).useDefault().Trim();
                }
                if (Pols[section].policyAt(page - 1).guidance() == "")
                {
                    GuidanceButton.Visible = false;
                }
                else
                {
                    GuidanceButton.Visible = true;
                }
                Pols[section].removePolicyAt(page - 2);
                if (!Pols[section].isPolicyAt(page - 1) && section == Pols.Count - 1)
                {
                    NextButton.Text = "Finish";
                    MarkAsDone.Visible = false;
                    NameLabel.Text = "";
                }
            }
            MarkAsDone.CheckedChanged -= MarkAsDone_CheckedChanged;
            MarkAsDone.Checked = false;
            MarkAsDone.CheckedChanged += MarkAsDone_CheckedChanged;
        }

        //The object for sections
        public class PolicySection
        {
            public string name;
            private string baseText;
            private string vulnText;
            private string invulnText;
            public int size;
            private List<Vulnerabilites> vulnerabilites = new List<Vulnerabilites>();
            private List<Policy> sectionPolicies = new List<Policy>();
            private bool safe;

            public PolicySection(XmlNode node)
            {
                size = Int32.Parse(node.Attributes["number"].Value);
                var iternode = node.FirstChild;
                name = iternode.InnerText;
                iternode = iternode.NextSibling;
                baseText = iternode.InnerText;
                iternode = iternode.NextSibling;
                vulnText = iternode.InnerText;
                iternode = iternode.NextSibling;
                invulnText = iternode.InnerText;
                iternode = iternode.NextSibling;
                foreach(XmlNode v in iternode.ChildNodes)
                {
                    vulnerabilites.Add(new Vulnerabilites(v));
                }
                iternode = iternode.NextSibling;
                foreach (XmlNode p in iternode.ChildNodes)
                {
                    if (p.Name == "Policy") { 
                    sectionPolicies.Add(new Policy(p));
                    }
                }
            }

            public string headerText(Dictionary<string, int> Policies)
            {
                List<int> vulns = new List<int>();
                int i = 0;
                foreach (Policy p in sectionPolicies)
                {
                    if (Policies.ContainsKey(p.name))
                    {
                        if (!p.isRecommended(Policies[p.name])) vulns.Add(i);
                    }
                    else
                    {
                        if (!p.isRecommended(-1)) vulns.Add(i);
                    }
                    i++;
                }
                String header = baseText.Trim()+Environment.NewLine;
                safe = vulns.Count == 0;
                if (safe) return header + invulnText.Trim();
                else
                {
                    String vulnStr = "";
                    foreach (Vulnerabilites v in vulnerabilites) vulnStr += v.vulnerabilites(vulns).Trim();
                    header += vulnText.Trim() + Environment.NewLine+ Environment.NewLine;
                    if (vulnStr.Length > 0) header=header.Replace("%EXAMPLES?%", " Some examples are given below.");
                    else header=header.Replace("%EXAMPLES?%", "");
                    header += vulnStr;

                }
                return header;
            }

            public Policy policyAt(int index)
            {
                return sectionPolicies[index];
            }

            public bool isPolicyAt(int index)
            {
                return index < size && index >= 0;
            }

            public void removePolicyAt(int index)
            {
                if (index < size && index >= 0)
                {
                    sectionPolicies.RemoveAt(index);
                    size -= 1;
                }
            }

            public bool isSafe()
            {
                return safe;
            }
        }

        //The object for vulnerabilities
        public class Vulnerabilites
        {
            private string vulnString;
            private int position;

            public Vulnerabilites(XmlNode node)
            {
                vulnString = node.InnerText;
                position = Int32.Parse(node.Attributes["position"].Value);
            }

            public string vulnerabilites(List<int> pols)
            {
                return (pols.Contains(position)) ? "\n"+vulnString : "";
            }
        }

        //The object for individual policies
        public class Policy
        {
            private int Default;
            private string[] Advice;
            private int[] LThresholds;
            private int[] UThresholds;
            private string Guidance;
            public string name;
            private int Recommended;
            public string NRColour;
            public string RColour;


            public Policy(XmlNode polNode)
            {
                name = polNode.Attributes["name"].InnerText;
                Default = Int32.Parse(polNode.Attributes["default"].InnerText);
                Recommended = Int32.Parse(polNode.Attributes["recommended"].InnerText);
                RColour = (polNode.Attributes["recommendedColour"]==null)?null: polNode.Attributes["recommendedColour"].InnerText;
                NRColour = (polNode.Attributes["nonRecommendedColour"] == null) ? null : polNode.Attributes["nonRecommendedColour"].InnerText;
                Guidance = polNode.FirstChild.InnerText;
                var num = 0;

                var size = polNode.ChildNodes[1].ChildNodes.Count;
                Advice = new string[size];
                LThresholds = new int[size];
                UThresholds = new int[size];

                foreach (XmlNode node in polNode.ChildNodes[1].ChildNodes)
                {
                    var thre = node.Attributes["threshold"].InnerText.Split('-');
                    LThresholds[num] = Int32.Parse(thre[0]);
                    UThresholds[num] = Int32.Parse(thre[1]);
                    Advice[num] = node.InnerText;
                    num++;
                }
            }

            public string check(int num)
            {

                for (var i = 0; i < Advice.Length; i++){
                    if (num <= UThresholds[i] && num >= LThresholds[i])
                    {
                        return Advice[i].Replace("%NUM%",num.ToString());
                    }
                }
                return "";
            }

            public string guidance()
            {
                return Guidance;
            }

            public string useDefault()
            {
                return check(Default);
            }

            public string getName()
            {
                return name;
            }

            public bool isRecommended(int val) //-1 is default
            {
                if (val == -1) val = Default;
                return val >= LThresholds[Recommended] && val <= UThresholds[Recommended];
            }

            public Color nonRecColour()
            {
                if (NRColour == null)
                {
                    return Color.Red;
                }
                else
                {
                    return Color.FromName(NRColour);
                }
            }

            public Color recColour()
            {
                if (RColour == null)
                {
                    return Color.Green;
                }
                else
                {
                    return Color.FromName(RColour);
                }
            }
        }

        //Shows guidance
        private void GuidanceButton_Click(object sender, EventArgs e)
        {
            MessageBox.Show(Pols[section].policyAt(page-2).guidance().Trim());
        }

        //Helper function to find named child in xml
        public XmlNode GetChildByName(XmlNode node,string name)
        {
            XmlNode child = node.FirstChild;
            while (child != null&&child.Name != name)
            {
                child = child.NextSibling;
            }
            return child;
        }
    
        //Skip the current section
        private void SkipButton_Click(object sender, EventArgs e)
        {
            page = Pols[section].size+1;
            NextButton_Click(sender, e);
        }
    }
}
