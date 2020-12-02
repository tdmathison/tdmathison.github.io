---
title: "Digging into obfuscated excel formula code"
author: Travis Mathison
date: 2020-10-02 21:33:00 -0700
categories: [Blogging, Malware-Analysis]
tags: [malware, excel, scripts, macros, phishing]
---

## Intro
A large amount of malware that targets businesses is through phishing attacks, and that is no different where I work.  We have been getting an influx of excel attachments in phishing documents and instead of having easy to extract VB macro code it is instead large amounts of obfuscated formula code.

This post is specifically to talk about some static analysis performed at that stage of the analysis and the custom python I wrote in an attempt to get some insight into what it may be doing.

## The sample and supporting code
I have uploaded the sample to VirusTotal and have created a GitHub repository with the python code discussed here and example output.

**VirusTotal:**<br />
[https://www.virustotal.com/gui/file/0aae8be1164f7c19c2c7215030b907d1ddefb186b7da77687ddccc4731267474/detection](https://www.virustotal.com/gui/file/0aae8be1164f7c19c2c7215030b907d1ddefb186b7da77687ddccc4731267474/detection)

**GitHub:**<br />
[https://github.com/tdmathison/ExcelFormulaExtractor](https://github.com/tdmathison/ExcelFormulaExtractor)

## Password protected excel workbook
Before looking at the code there are two things that may be pitfalls.  First is that in this case the excel sheet is password protected (but we have the password as it was given in the phishing email it came from), secondly, when you export excel tabs to CSV files you may "lose data" if not careful.

### Removing password protection from excel document
To remove password protection on the excel document you can utilize the [msoffcrypto-crack.py](https://blog.didierstevens.com/2018/12/31/new-tool-msoffcrypto-crack-py/) script.  This is installed and ready for use within the FireEye FlareVM.

```
pass.txt contains:
F0409!

Command:
PS C:\Users\flarevm\Desktop\6050874161397760> & 'C:\Python27\python.exe' C:\Tools\msoffcrypto-crack\msoffcrypto-crack.py -p .\pass.txt -o decrypted.xls .\sample.xls
Password found: F0409!
```

This will create a new file called decrypted.xls that will no longer prompt for a password.

### Exporting excel workbook tabs as CSV files
To export tabs to CSV files you simply need to:
* Select the tab you want to export
* Select File->Export->Change File Type and select "CSV (Comma delimited)(*.csv)

**The catch:**<br /> 
In the case of formulas that reference specific columns and rows we need to preserve this in the exported data.  When you export you may LOSE this data by excel eliminating many columns or rows that did not contain data.  Formulas in malware often embed themselves dozens or hundreds of columns deep.

**The solution:**<br />
All you need to do is enter a single value into the A1 cell.  Just enter the number "1" before performing the export to CSV and it will capture the complete document and preserve the columns and rows needed for analysis.

## Observing the malwares formula code
When observing the Name Manager in the excel book I saw an Auto_Open value that refered to =I!$CS$25895 and this is where I saw the initial formula code which I quickly realized was obfuscated to make it difficult to make sense of.

<img src="{{ site.url }}/assets/img/blogging/excel_01.png"/>

Following the formula code jumping around shows how painful this would be to manually attempt to follow.

<img src="{{ site.url }}/assets/img/blogging/excel_02.png"/>

## The programatic solution
In an attempt to solve this problem I had two specific requirements:<br />
1) Since specific cells were referenced by name such as $AB$50741 I needed to make sure I built a table were they could be referenced<br />
2) I needed a way to start with a value in a given cell and then merge the content into the string by replacing the cell location text

All that would be left is applying step 2 over and over until there are no more cell location strings to replace.

### Dumping content into hashmap
The first part is achieved by creating a hashmap and reading through all delimited data and adding it to the hashmap with the key being the formatted location of the cell that would be referenced in the formula code.

``` python
excel_data = {}

# Locates all excel sheet cells with data and saves the cell location as a key and the content as the value
def dump_excel_sheet_values(filepath):
    with open(filepath) as file:
        lines = file.readlines()
        for row, row_values in enumerate(lines):
            values = row_values.split(',')
            for col, col_value in enumerate(values):
                value_to_save = col_value.strip().replace('\n', '\\n')
                if value_to_save:
                    excel_data[str.format("${}${}", get_col_name(col + 1), row + 1)] = value_to_save

dump_excel_sheet_values(sys.argv[1])
```

With this we can dump out the content and display the proper cell location as shown in the partial snippet below:
```
$A$1: 1
$BM$65: 19053
$BM$66: 40
$HC$292: i
$AH$462: a
$HE$736: w
$AR$982: J
$AC$1180: h
$DP$1387: d
$DV$1540: Y
$FS$1919: P
$IM$2401: Y
$DS$2454: e
$FO$2480: N
$DX$2684: EsNDtISBBnaCXk=$HF$26301&$EB$37517&$Y$59856&$H$23233&$FR$26455&$BK$49458&$P$23617&$FU$38413&$G$15199&$DF$13040
$DX$2685: ygxjnNCysLIfB=$GC$31380
$DX$2686: =$ER$4739()
$DX$2687: =RUN($AX$7390)
```

### Reconstructing the formula strings into something useful
The final step is to take all of these obfuscated strings and merge in the content of all the cell location references.  I made a simple function that will do this for the first cell location is find (via regex search).  In the end, this function just gets applied to the string over and over until it can no longer find any more references to other cells.

``` python
# Checks if the string concatenates other cell data and merges the first occurrence in
def reconstruct(data):
    result = re.search(regexp_cell_pos, data)
    if result:
        data_modified = data[0: result.start()]

        if data[result.start(): result.end()] in excel_data.keys():
            # merge in the content from the referenced cell
            data_modified += excel_data[data[result.start(): result.end()]]
        else:
            # blank cell that is used to store values at runtime
            data_modified += '(var-cell)'

        data_modified += data[result.end() + 1:]

        return repair(data_modified)

    return None
```

Finally, we loop through every key we populated and see how much it can merge together.  Some cells are just single characters that are used to concatenate text together and some cells make 10+ cell references.

``` python
# Run through each key and attempt to reconstruct
for key in excel_data:
    print("Initial: {}".format(excel_data[key]))

    new_val = reconstruct(excel_data[key])
    new_string = new_val

    while new_val:
        print(new_val)
        new_string = new_val
        new_val = reconstruct(new_string)

    if (new_string is not None) and (new_string != '(var-cell)'):
        final_strings.append(new_string)

    print("Final: {}".format(new_string))
    print("********************************************************")
```

### Results
The resulting output is very large so an couple examples of where the value came out of this are:

**Showing it resolve a Win32 function**
```
Initial: =RUN($II$26959)
=RUN(EsNDtISBBnaCXk=$EI$48049&$U$22638&$EO$25738&$FR$34525&$AP$37942&$B$6338&$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=S$U$22638&$EO$25738&$FR$34525&$AP$37942&$B$6338&$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=Sh$EO$25738&$FR$34525&$AP$37942&$B$6338&$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=She$FR$34525&$AP$37942&$B$6338&$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=Shel$AP$37942&$B$6338&$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=Shell$B$6338&$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellE$CQ$36635&$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellEx$DS$2454&$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellExe$AW$53450&$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellExec$DA$9220&$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellExecu$FX$55530&$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellExecut$DO$26222&$CV$8941
=RUN(EsNDtISBBnaCXk=ShellExecute$CV$8941
=RUN(EsNDtISBBnaCXk=ShellExecuteA
Final: =RUN(EsNDtISBBnaCXk=ShellExecuteA
```

**Showing it resolve the C&C URL**<br />
*NOTE: I have intentionally broken the link text formulated below.*
``` text
Initial: EsNDtISBBnaCXk=$W$27806&$DB$48425&$CG$29888&$GH$57090&$EK$3388&$BT$55498&$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=h$DB$48425&$CG$29888&$GH$57090&$EK$3388&$BT$55498&$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=ht$CG$29888&$GH$57090&$EK$3388&$BT$55498&$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=htt$GH$57090&$EK$3388&$BT$55498&$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=http$EK$3388&$BT$55498&$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https$BT$55498&$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https:$IL$29507&$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https:/$CR$10941&$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://$U$21547&$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://c$GY$4902&$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://co$AE$53306&$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://com$BX$30413&$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://comp$FG$27124&$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://compo$BV$30953&$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://compon$IM$56694&$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://compone$EV$38328&$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://componen$CF$15512&$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component$EG$30041&$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component.$DZ$15836&$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component.p$ET$32765&$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw$CQ$47333&$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/$HE$736&$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/w$V$24861&$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp$DP$11026&$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-$FA$21247&$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-i$CD$7333&$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-in$AK$10221&$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-ind$HH$23769&$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-inde$DK$39723&$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-index$BH$15533&$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-index.$AC$35202&$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-index.p$CT$11282&$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-index.ph$EY$36257
EsNDtISBBnaCXk=https ://component[.]pw/wp-index.php
Final: EsNDtISBBnaCXk=https ://component[.]pw/wp-index.php
```

At the end, a dump of the final text strings are listed.  This is where you can find IoC's, Win32 calls, paths to executables that may be dropped, the C&C path that we see here (and I verified it calls out to with FakeNet running).
```
Final strings list:
===========================================
EsNDtISBBnaCXk=C:\jhmKRYC
ygxjnNCysLIfB=(var-cell)
="=RETURN(FORMULA.FILL(EsNDtISBBnaCXk)
=RUN(EsNDtISBBnaCXk=C:\jhmKRYC\POeikcC
EsNDtISBBnaCXk=cmhKasNg
ygxjnNCysLIfB=(var-cell)
="=RETURN(FORMULA.FILL(EsNDtISBBnaCXk)
=RUN(EsNDtISBBnaCXk=dTyIIHMw
EsNDtISBBnaCXk=CreateDirectoryA
EsNDtISBBnaCXk=Shell32
=RUN(EsNDtISBBnaCXk=ShellExecuteA
EsNDtISBBnaCXk=C:\jhmKRYC\POeikcC
EsNDtISBBnaCXk=DownloadFile
=RUN(EsNDtISBBnaCXk=C:\jhmKRYC\POeikcC\XqwFtZi.exe

... and more
```

## Conclusion
This was an exercise to see how much I could learn from this formula code through static analysis.  Many of the findings from above were observed during dynamic analysis but not all.  The more information you have before dynamic analysis the more you can knowingly watch out for and attempt to observe.  The downside of dynamic analysis is that you only see the path the malware takes during that detonation and you may miss a lot of what the malware could potentially do.

Full code to above project is in the [https://github.com/tdmathison/ExcelFormulaExtractor](https://github.com/tdmathison/ExcelFormulaExtractor) repo.