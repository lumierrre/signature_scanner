#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

int MZfunc(FILE* f, int* IsExe)
{
    int res;
    unsigned char mz[2];
    if (f == NULL) return 1;
    if (IsExe == NULL) return 2;
    *IsExe = 0;
    res = fread(mz, sizeof(mz[0]), sizeof(mz)/sizeof(mz[0]), f);
    if (res != sizeof(mz)/sizeof(mz[0])) return 3;
    if ((mz[0]!='M')||(mz[1]!='Z')) *IsExe = 1;
    return 0;
}

int FileSizeFunc(FILE* f, long int sm, size_t SizeSig, int* SizeCheck)
{
    int res;
    long int FileSize;
    if (f == NULL)return 1;
    if (SizeCheck == NULL) return 2;
    *SizeCheck = 0;
    res = fseek(f, 0, SEEK_END);
    if (res != 0) return 3;
    FileSize = ftell(f);
    if (FileSize == -1) return 4;
    if (sm + SizeSig > FileSize) *SizeCheck = 1;
    return 0;
}

struct Virus
{
    char Name[100];
    unsigned char Sig[8];
    long int sm;
};

int main()
{
    FILE* f;
    size_t i, SizeSig;
    int res, IsExe, SizeCheck, flag = 0;
    char FilePath[1000];
    unsigned char NewSig[8];
    f = fopen("VirusBase.txt", "r");
    if (f == NULL)
    {
        printf("\nsorry, base of viruses is not found\n");
        return 1;
    }
    struct Virus a;
    res = fscanf(f, "%[^\n]", a.Name);
    if (res != 1)
    {
        printf("\nerror in read virus name\n");
        fclose(f);
        return 2;
    }
    for (i = 0; i < sizeof(a.Sig)/sizeof(a.Sig[0]); i++)
    {
        res = fscanf(f, "%hhx", &a.Sig[i]);
        if (res != 1)
        {
            printf("\nerror in read virus signature\n");
            fclose(f);
            return 3;
        }
    }
    res = fscanf(f, "%lx", &a.sm);
    if (res != 1)
    {
        printf("\nerror in read virus seek\n");
        fclose(f);
        return 4;
    }
    res = fclose(f);
    if (res != 0)
    {
        printf("\nerror of closing fail\n");
        return 5;
    }
    res = printf("Enter path to check fail: ");
    if (res < 0)
    {
        printf("\nerror vivoda\n");
        return 6;
    }
    res = scanf("%[^\n]", FilePath);
    if (res != 1)
    {
        printf("\nerror vvoda\n");
        return 7;
    }
    f = fopen(FilePath, "rb");
    if (f == NULL)
    {
        printf("\nsorry, fail is not found\n");
        return 8;
    }
    res = MZfunc(f, &IsExe); //the first fuction
    if (res != 0)
    {
        printf("\nerror in (or of?) function work\n");
        fclose(f);
        return 9;
    }
    if (IsExe == 1)
    {
        res = printf("\nfile is clear\n");
        if (res < 0)
        {
            printf("\nerror vivoda\n");
            fclose(f);
            return 10;
        }
        res = fclose(f);
        if (res != 0)
        {
            printf("\nerror of closing fail\n");
            return 11;
        }
        return 0;
    }
    SizeSig = sizeof(a.Sig)/sizeof(a.Sig[0]);
    res = FileSizeFunc(f, a.sm, SizeSig, &SizeCheck); //the second function
    if (res != 0)
    {
        printf("\nerror in function work\n");
        fclose(f);
        return 12;
    }
    if (SizeCheck == 1)
    {
        res = printf("\nfile is clear\n");
        if (res < 0)
        {
            printf("\nerror vivoda\n");
            fclose(f);
            return 13;
        }
        res = fclose(f);
        if (res != 0)
        {
            printf("\nerror of closing fail\n");
            return 14;
        }
        return 0;
    }
    res = fseek(f, a.sm, SEEK_SET);
    if (res != 0)
    {
        printf("\nerror perehoda po seek\n");
        fclose(f);
        return 15;
    }
    res = fread(NewSig, sizeof(NewSig[0]), sizeof(NewSig)/sizeof(NewSig[0]), f);
    if (res != sizeof(NewSig)/sizeof(NewSig[0]))
    {
        printf("\nerror in read signature of checking fail\n");
        fclose(f);
        return 16;
    }
    for (i=0; i < sizeof(a.Sig)/sizeof(a.Sig[0]); i++)
    {
        if (a.Sig[i] != NewSig[i])
        {
            flag = 1;
            break;
        }
    }
    if (flag == 1)
    {
        res = printf("\nvictory, file is clear\n");
        if (res < 0)
        {
            printf("\nerror vivoda\n");
            fclose(f);
            return 17;
        }
    }
    else
    {
        res = printf("\nfile is NOT clear, virus %s detected\n", a.Name);
        if (res < 0)
        {
            printf("\noutput error\n");
            fclose(f);
            return 18;
        }
    }
    res = fclose(f);
        if (res != 0)
        {
            printf("\nerror of closing fail\n");
            return 19;
        }
    return 0;
}
