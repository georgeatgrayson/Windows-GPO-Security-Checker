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
using System.Text.RegularExpressions;

namespace WindowsFormsApp1
{
    public partial class Update : Form
    {
        private int num;
        public string editPath;

        public Update()
        {
            InitializeComponent();
        }

        public Form1 form;

        private void Update_Load(object sender, EventArgs e)
        {
            //num = form.page - 1;
            //ValueSelect.Maximum = form.Pols[num].maximumSetting;
            //ValueSelect.Minimum = form.Pols[num].minimumSetting;
            //HeaderLabel.Text = form.Pols[num].header;
            //UnitLabel.Text = form.Pols[num].unit;
            //DescriptionLabel.Text = form.Pols[num].description;
            //ValueSelect.Value = Decimal.Parse(form.Pols[num].recVal);
        }

        private void ValueSelect_ValueChanged(object sender, EventArgs e)
        {
            //form.Pols[num].updateAdvice(AdviceLabel, (int) ValueSelect.Value);
        }

        private void setReccom_Click(object sender, EventArgs e)
        {
            //ValueSelect.Value = Decimal.Parse(form.Pols[num].recVal);
        }

        private void CancelButton_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void OKButton_Click(object sender, EventArgs e)
        {
            //string text = File.ReadAllText(editPath);
            //Regex rgx = new Regex(form.Pols[num].name+"\\s=\\s^\\n");
            //text = rgx.Replace(text, form.Pols[num].name + ValueSelect.Value + "\\n");

            //var p = form.gpo.Path;

            //File.WriteAllText(editPath,text);
            //form.gpo.Import(form.gpb);
            //this.Close();
        }
    }
}
