from Strategies.getFileType import FileType, getFileType, CSV_DELIMITER

# Test all provided input files are detected correctly
assert(getFileType("Binaries/csv1.txt") == FileType.csv)
assert(getFileType("Binaries/csv2.txt") == FileType.csv)
assert(getFileType("Binaries/plaintext1.txt") == FileType.plaintext)
assert(getFileType("Binaries/plaintext2.txt") == FileType.plaintext)
assert(getFileType("Binaries/plaintext3.txt") == FileType.plaintext)
assert(getFileType("Binaries/json1.txt") == FileType.json)
assert(getFileType("Binaries/json2.txt") == FileType.json)
assert(getFileType("Binaries/xml1.txt") == FileType.xml)
assert(getFileType("Binaries/xml2.txt") == FileType.xml)
assert(getFileType("Binaries/xml3.txt") == FileType.xml)

# Test elf, pdf and jpeg are detected
assert(getFileType("test/abs") == FileType.elf)
assert(getFileType("test/pdf.pdf") == FileType.pdf)
assert(getFileType("test/jpeg1.jpg") == FileType.jpeg)

# zip files should NOT be mistaken for csv
# return fileType unhandled since you cant called .read() on them normally
assert(getFileType("test/zip.txt") == FileType.unhandled)

# files that look like csv but aren't
assert(getFileType("test/badcsv1") == FileType.plaintext)

# Looks like badcsv but is actually valid
assert(getFileType("test/badcsv2") == FileType.csv)

print("All Tests Passed!")