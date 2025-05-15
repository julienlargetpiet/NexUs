package main 

import (
  "fmt"
  "os"
  "bytes"
  "io"
  "compress/zlib"
  "path/filepath"
  "encoding/hex"
  //"crypto"
  //"crypto/rand"
  //"crypto/rsa"
  "crypto/sha256"
  //"net"
)

var base_dir string = "/home/kvv/ssd1/NexUs/dir_client/"
var ref_nb = [10]uint8{'0', '1', '2', '3', '4', 
                       '5', '6', '7', '8', '9'}

func GoodIP(x *string) bool {
  var n int  = len(*x)
  var i int = 0
  var i2 int
  var cur_val string
  for I := 0; I < 3; I++ {
    cur_val = ""
    for i < n && (*x)[i] != '.' {
      i2 = 0
      for i2 < 10 {
        if ref_nb[i2] != (*x)[i] {
          i2++
        } else {
          break
        }
      }
      if i2 == 10 {
        return false
      }
      cur_val += string((*x)[i])
      i++
    }
    if len(cur_val) > 3 || len(cur_val) == 0 {
      return false
    }
    i++
  }
  cur_val = ""
  for i < n {
    i2 = 0
    for i2 < 10 {
      if ref_nb[i2] != (*x)[i] {
        i2++
      } else {
        break
      }
    }
    if i2 == 10 {
      return false
    }
    cur_val += string((*x)[i])
    i++
  }
  if len(cur_val) > 3 || len(cur_val) == 0 {
    return false
  }
  return true
}

func GoodPort(x *string) bool {
  var i2 int
  for i := 0; i < len(*x); i++ {
    i2 = 0
    for i2 < 10 {
      if (*x)[i] != ref_nb[i2] {
        i2++
      } else {
        break
      }
    }
    if i2 == 10 {
      return false
    }
  }
  int_port := StringToInt(*x)
  if int_port < 5000 || int_port > 90000 {
    return false
  }
  return true
}

func VerifHost(x *string) (bool, string) {
  cur_val := ""
  var i int = 0
  var n int = len(*x)
  for i < n && (*x)[i] != ':' {
    cur_val += string((*x)[i])
    i++
  }
  if i == n {
    return false, "no port provided"
  }
  i++ 
  if i == n {
    return false, "no port provided"
  }
  is_valid := GoodIP(&cur_val)
  if !is_valid {
    return false, "the ip is not a valid ip format"
  }
  cur_val = ""
  for i < n {
    cur_val += string((*x)[i])
    i++
  }
  is_valid = GoodPort(&cur_val)
  if !is_valid {
    return false, "the port is not valid"
  }
  return true, ""
}

func StringToInt(x string) int {
  var ref_nb = [10]uint8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
  var rtn_val int = 0
  var lngth int = len(x)
  var i2 int
  var cur_rn uint8
  var i int
  for i = 0; i + 1 < lngth; i++ {
    cur_rn = x[i]
    i2 = 0
    for cur_rn != ref_nb[i2]{
      i2++
    }
    rtn_val += i2
    rtn_val *= 10
  }
  cur_rn = x[i]
  i2 = 0
  for cur_rn != ref_nb[i2]{
    i2++
  }
  rtn_val += i2
  return rtn_val
}

func Union(f1 *string, f2 *string) ([]string, error) {
  var frst_sl []string
  var scd_sl []string
  var cur_val string
  var rtn_sl []string
  data, err := os.ReadFile(*f1)
  if err != nil {
    return rtn_sl, err
  }
  str_data := string(data)
  cur_val = ""
  var i int = 0
  str_data += "\n"
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      frst_sl = append(frst_sl, cur_val)
      cur_val = ""
    }
    i++
  }
  data, err = os.ReadFile(*f2)
  if err != nil {
    return rtn_sl, err
  }
  str_data = string(data)
  i = 0
  cur_val = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      scd_sl = append(scd_sl, cur_val)
      cur_val = ""
    }
    i++
  }
  var i2 int
  var n2 = len(scd_sl)
  i = 0
  for i < len(frst_sl) {
    i2 = 0
    cur_val = frst_sl[i]
    for i2 < n2 {
      if cur_val == scd_sl[i2] {
        rtn_sl = append(rtn_sl, cur_val)
        break
      }
      i2++
    }
    i++
  }
  return rtn_sl, nil
}

func DisplayDiff(file1 *string, file2 *string, sep *string) error {
  var dataa string
  var datab string
  var comp bool = true
  data, err := os.ReadFile(*file1)
  if err != nil {
    return err
  }
  data, err = deCompress(&data)
  if err != nil {
    return err
  }
  str_data := string(data)
  var sl_str_data1 []string
  var sl_str_data2 []string
  var i int = 0
  var cur_val string = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data1 = append(sl_str_data1, cur_val)
      cur_val = ""
    }
    i++
  }
  data, err = os.ReadFile(*file2)
  if err != nil {
    return err
  }
  data, err = deCompress(&data)
  if err != nil {
    return err
  }
  str_data = string(data)
  i = 0
  cur_val = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data2 = append(sl_str_data2, cur_val)
      cur_val = ""
    }
    i++
  }
  i = 0
  var i2 int = 0
  n := len(sl_str_data1)
  n2 := len(sl_str_data2)
  for comp && i < n2 {
    datab = sl_str_data2[i]
    dataa = sl_str_data1[i]
    for datab != dataa && i2 < n {
      fmt.Printf("%v%v -\n", dataa, *sep)
      i2++
      dataa = sl_str_data1[i2]
    }
    comp = (datab == dataa)
    if comp {
      fmt.Printf("%v%v%v\n", dataa, *sep, datab)
    } else {
      fmt.Printf("%v+ %v\n", *sep, datab)
    }
    i++
  }
  for i < n2 {
    datab = sl_str_data2[i]
    fmt.Printf("%v+ %v\n", *sep, datab)
    i++
  }
  if comp {
    for i2 < n {
      dataa = sl_str_data1[i2]
      fmt.Printf("%v- %v\n", dataa, *sep)
      i2++
    }
  }
  return nil
}

func DisplayDiffCommit(file1 *string, file2 *string, sep *string) error {
  var dataa string
  var datab string
  var comp bool = true
  data, err := os.ReadFile(*file1)
  if err != nil {
    return err
  }
  str_data := string(data)
  var sl_str_data1 []string
  var sl_str_data2 []string
  var i int = 0
  var cur_val string = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data1 = append(sl_str_data1, cur_val)
      cur_val = ""
    }
    i++
  }
  data, err = os.ReadFile(*file2)
  if err != nil {
    return err
  }
  str_data = string(data)
  i = 0
  cur_val = ""
  for i < len(str_data) {
    if str_data[i] != '\n' {
      cur_val += string(str_data[i])
    } else {
      sl_str_data2 = append(sl_str_data2, cur_val)
      cur_val = ""
    }
    i++
  }
  i = 0
  var i2 int = 0
  n := len(sl_str_data1)
  n2 := len(sl_str_data2)
  for comp && i < n2 {
    datab = sl_str_data2[i]
    dataa = sl_str_data1[i]
    for datab != dataa && i2 < n {
      fmt.Printf("%v%v -\n", dataa, *sep)
      i2++
      dataa = sl_str_data1[i2]
    }
    comp = (datab == dataa)
    if comp {
      fmt.Printf("%v%v%v\n", dataa, *sep, datab)
    } else {
      fmt.Printf("%v+ %v\n", *sep, datab)
    }
    i++
    i2++
  }
  for i < n2 {
    datab = sl_str_data2[i]
    fmt.Printf("%v + %v\n", *sep, datab)
    i++
  }
  if comp {
    for i2 < n {
      dataa = sl_str_data1[i2]
      fmt.Printf("%v - %v\n", dataa, *sep)
      i2++
    }
  }
  return nil
}

func Compress(x *[]byte) ([]byte, error) {
  var b bytes.Buffer
  w := zlib.NewWriter(&b)
  _, err := w.Write(*x)
  if err != nil {
    return nil, err
  }
  err = w.Close()
  if err != nil {
    return nil, err
  }
  return b.Bytes(), nil
}

func deCompress(x *[]byte) ([]byte, error) {
  r, err := zlib.NewReader(bytes.NewReader(*x))
  if err != nil {
    return nil, err
  }
  var rtn_data bytes.Buffer
  _, err = io.Copy(&rtn_data, r)
  if err != nil {
    return nil, err
  }
  return rtn_data.Bytes(), nil
}

func ExistDirFile(x *string, file_name *string) (bool, error) {
  data, err := os.ReadFile(*file_name)
  var cur_val string = ""
  if err != nil {
    return false, err
  }
  n := len(*x)
  var i2 int
  for i := 0; i < len(data); i++ {
    if data[i] != 10 {
      cur_val += string(data[i])
    } else {
      if n == len(cur_val) {
        i2 = 0
        for i2 < len(cur_val) {
          if (*x)[i2] != cur_val[i2] {
            break
          }
          i2++
        }
        if i2 == n {
          return true, nil 
        }
      }
      cur_val = ""
    }
  }
  return false, nil
}

func ExistDirFile2(x *string, file_name *string) (bool, string, error) {
  data, err := os.ReadFile(*file_name)
  var cur_val string = ""
  if err != nil {
    return false, "", err
  }
  n := len(*x)
  var i2 int
  var n2 int
  var pre_rtn []string
  var i int
  var cur_int int = 0
  var cur_idx int = 0
  for i = 0; i < len(data); i++ {
    if data[i] != 10 {
      cur_val += string(data[i])
    } else {
      n2 = len(cur_val)
      if n >= n2 {
        i2 = 0
        for i2 < n2 {
          if (*x)[i2] != cur_val[i2] {
            break
          }
          i2++
        }
        if i2 == n2 {
          pre_rtn = append(pre_rtn, cur_val)
        }
      }
      cur_val = ""
    }
  }
  if len(pre_rtn) > 0 {
    for i2 = 0; i2 < len(pre_rtn); i2++ {
      if len(pre_rtn[i2]) > cur_int {
        cur_int = len(pre_rtn[i2])
        cur_idx = i2
      }
    }
    return true, pre_rtn[cur_idx], nil
  } else {
    return false, "", nil
  }
}

func ExistDirFile3(x *string, file_name *string) (bool, string, error) {
  data, err := os.ReadFile(*file_name)
  var cur_val string = ""
  if err != nil {
    return false, "", err
  }
  n := len(*x)
  var i2 int
  rtn_str := ""
  var rtn_bool bool = false
  for i := 0; i < len(data); i++ {
    if data[i] != 10 {
      cur_val += string(data[i])
    } else {
      if n == len(cur_val) {
        i2 = 0
        for i2 < len(cur_val) {
          if (*x)[i2] != cur_val[i2] {
            break
          }
          i2++
        }
        if i2 == n {
          rtn_bool = true
          cur_val = ""
        }
      }
      rtn_str += cur_val
      rtn_str += "\n"
      cur_val = ""
    }
  }
  return rtn_bool, rtn_str, nil
}

func Tree(src string) ([]string, error) {
  var cur_path string
  var cur_path_dir_found string
  var vec_dirname = []string{src}
  var data []byte
  var n int = 0
  var rtn_data = []string{src}
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
        rtn_data = append(rtn_data, cur_path_dir_found)
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return rtn_data, err
        }
        rtn_data = append(rtn_data, string(data))
      }
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  return rtn_data, nil
}

func TreeSum(src string) ([32]byte, error) {
  var cur_path string
  var cur_path_dir_found string
  var vec_dirname = []string{src}
  var data []byte
  var n int = 0
  var all_data []byte
  var rtn_data [32]byte
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return rtn_data, err
        }
        all_data = append(all_data, data...)
      }
      all_data = append(all_data, []byte(v.Name())...)
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  rtn_data = sha256.Sum256(all_data)
  return rtn_data, nil
}

func CopyDir(src *string, dst *string) error {
  var cur_path string
  var cur_path2 string
  var cur_path_dir_found string
  var vec_dirname = []string{*src}
  var n int = 0
  var data []byte
  var ovr int = len(*src)
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
        cur_path2 = *dst + cur_path_dir_found[ovr:]
        err = os.Mkdir(cur_path2, 0755)
        if err != nil {
          return err
        }
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return err
        }
        cur_path2 = *dst + cur_path[ovr:]
        err = os.WriteFile(cur_path2 + "/" + v.Name(), data, 0644)
        if err != nil {
          return err
        }
      }
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  return nil
}

func deCompressCopyDir(src *string, dst *string) error {
  var cur_path string
  var cur_path2 string
  var cur_path_dir_found string
  var vec_dirname = []string{*src}
  var n int = 0
  var data []byte
  var ovr int = len(*src)
  var dc_data []byte
  for n > -1 {
    cur_path = vec_dirname[n]
    entries, err := os.ReadDir(cur_path)
    for _, v := range entries {
      if v.IsDir() {
        cur_path_dir_found = cur_path + "/" + v.Name()
        vec_dirname = append([]string{cur_path_dir_found}, vec_dirname...)
        cur_path2 = *dst + cur_path_dir_found[ovr:]
        err = os.Mkdir(cur_path2, 0755)
        if err != nil {
          return err
        }
        n += 1
      } else {
        data, err = os.ReadFile(cur_path + "/" + v.Name())
        if err != nil {
          return err
        }
        dc_data, err = deCompress(&data)
        if err != nil {
          return err
        }
        cur_path2 = *dst + cur_path[ovr:]
        err = os.WriteFile(cur_path2 + "/" + v.Name(), dc_data, 0644)
        if err != nil {
          return err
        }
      }
    }
    vec_dirname = vec_dirname[:len(vec_dirname) - 1]
    n -= 1
  }
  return nil
}

func main() { 

  arg_v := os.Args
  var err error
  var file string
  var cur_val string
  var cur_val2 string
  var cur_val3 string
  var cur_val4 string
  var is_valid bool
  var data []byte
  var str_data string
  initiated_repo := base_dir + "initiated.txt"
  cur_dir, _ := filepath.Abs(".")
  n := len(arg_v)
  var i int
  var i2 int

  if n == 1 {
    fmt.Println("Not enough argument")
    return
  }

  frst_arg := os.Args[1]

  if frst_arg == "help" {
    fmt.Println("Commands list:")
    fmt.Println("'init' is to initiate a repo, this will create a NexUs project for the current directory you are calling it from, this will automatically create a 'main' branch")
    fmt.Println("Example: nexus init\n")
    fmt.Println("'sethost' will bind a server ip and port to your current NexUs project")
    fmt.Println("Example: nexus sethost 12.12.12.12:5600\n")
    fmt.Println("'hostinfo' will tell you the host informations for your current NexUs project")
    fmt.Println("Example: nexus hostinfo\n")
    fmt.Println("'branchnew' is to create a branch, this will copy all the current files and directories from your current branch to a new one that you can modify without repercusion on other branches")
    fmt.Println("Example: nexus branchnew main2\n")
    fmt.Println("'branchlist' this will list all the branch available for your NexUs project")
    fmt.Println("Example: nexus branchlist\n")
    fmt.Println("'branchmy' this will print your current branch")
    fmt.Println("Example: nexus branchmy\n")
    fmt.Println("'branchswitch' will switch over the specified branch, bringing the last content of its commit to your current directory")
    fmt.Println("Example: nexus branchswitch main2\n")
    fmt.Println("'branchrm' will delete a branch")
    fmt.Println("Example: nexus branchrm main2\n")
    fmt.Println("'add' is to add files or directory to a temporary NexUs location called 'sas' before commiting")
    fmt.Println("Example: nexus add a.txt dira dira/*\n")
    fmt.Println("'rm' is to remove files or folders from your current directory and the 'sas'")
    fmt.Println("Example: nexus rm a.txt\n")
    fmt.Println("'commit' is to save the changes made to your project, after adding them into 'sas'")
    fmt.Println(`Example: nexus commit "message of the commit"` + "\n")
    fmt.Println("'commitlist' this will list all commit for the current branch, in chronological order")
    fmt.Println("Example: nexus commitlist\n")
    fmt.Println("'commitlast' this will print the last commit")
    fmt.Println("Example: nexus commitlast\n")
    fmt.Println("'commitmsg x' where x specifies the commit number, prints the message of thespecified commit")
    fmt.Println("Example: nexus commitmsg 5, will print the commit message of the fith commit\n")
    fmt.Println("'commitdiff x1 x2 file file' will print the diff between the specified file through 2 differents commits")
    fmt.Println("Example: commitdiff 2 3 a.txt a.txt ,will print the content diff between the content of a.txt through the third commit and the fourth commit\n")
    fmt.Println("'commitstructdiff x1 x2' will print the difference between the filestructure of 2 specified commits")
    fmt.Println("Example: nexus commitstructdiff 2 6 ,will print the filestructure difference between the third and the seventh commit\n")
    return
  }

  if frst_arg == "init" {
    if n > 2 {
      fmt.Println("Error: init does not require more arguments")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil { 
      fmt.Println("Error:", err)
      return
    }
    if is_valid {
      fmt.Println("Error: repo already initiated")
      return
    }
    is_valid, _, err = ExistDirFile2(&cur_dir, &initiated_repo)
    if err != nil { 
      fmt.Println("Error:", err)
      return
    }
    if is_valid {
      fmt.Println("Error: Can't initilize a repo within another initialize repo")
      return
    }
    cur_val = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val += "_"
      } else {
        cur_val += string(cur_dir[i])
      }
    }
    err = os.Mkdir(base_dir + cur_val, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.Mkdir(base_dir + cur_val + "/main", 0755)
    if err != nil {
      fmt.Println("Error1:", err)
      return
    }
    err = os.Mkdir(base_dir + cur_val + "/main/sas", 0755)
    if err != nil {
      fmt.Println("Error1:", err)
      return
    }
    err = os.Mkdir(base_dir + cur_val + "/main/data", 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/cur_added.txt", 
                       []byte(cur_dir + "\n"), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/is_pushed.txt", 
                       []byte(""), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/commits.txt", 
                       []byte(""), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/branches.txt", 
                       []byte("main\n"), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/cur_branch.txt", 
                       []byte("main"), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/host_info.txt", 
                       []byte("main\n"), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(base_dir + cur_val + "/main/cur_commit.txt", 
                       []byte(""), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (cur_dir + "\n")
    err = os.WriteFile(initiated_repo,
                       []byte(str_data), 
                       0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "add" {
    if n < 3 {
      fmt.Println("Error: not enough argument for add")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/cur_added.txt"
    var all_args []string
    var fileinfo os.FileInfo
    var tmp_val string
    var tmp_valv []string
    for i = 2; i < n; i++ {
      tmp_val = os.Args[i]
      if tmp_val[len(tmp_val) - 1] == '*' {
        tmp_val = tmp_val[:len(tmp_val) - 2]
        fileinfo, err = os.Stat(tmp_val)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        if fileinfo.IsDir() {
          tmp_valv, err = Tree(tmp_val)
          if err != nil {
            fmt.Println("Error:", err)
            return
          }
          all_args = append(all_args, tmp_valv...)
        } else {
          fmt.Println("Error: the statement '*' is only used to include all elements within a dir")
        }
      } else {
        all_args = append(all_args, tmp_val)
      }
    }
    for i = 0; i < len(all_args); i++ {
      cur_val4 = all_args[i]
      file = cur_dir + "/" + cur_val4
      is_valid, cur_val, err = ExistDirFile2(&file, &cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: files and/or folders non existing for the currrent initiated repos")
        return
      }
      if file == cur_val {
        fmt.Println("Error: file or directory already added for this commit")
        return
      }
      i2 = len(cur_val) + 1
      for i2 < len(file) - 1 {
        if file[i2] == '/' {
          fmt.Println("Error: Must include directories where the new element is being added")
          return
        }
        i2++
      }
      data, err = os.ReadFile(cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      str_data = string(data)
      str_data += (file + "\n")
      err = os.WriteFile(cur_val2, []byte(str_data), 0755)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      fileinfo, err = os.Stat(file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      var c_data []byte
      if !fileinfo.IsDir() {
        data, err = os.ReadFile(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        c_data, err = Compress(&data)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.WriteFile(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4, 
                           c_data,
                           0644)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Mkdir(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4, 0755)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    return
  }

  if frst_arg == "rm" {
    if n < 3 {
      fmt.Println("Error: not enough argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch + "/cur_added.txt"
    for i = 2; i < n; i++ {
      cur_val4 = os.Args[i]
      file = cur_dir + "/" + cur_val4
      is_valid, str_data, err = ExistDirFile3(&file, &cur_val2)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: files and/or folders non existing for the currrent commit")
        return
      }      
      err = os.WriteFile(cur_val2, []byte(str_data), 0755)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      fileinfo, err := os.Stat(file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if fileinfo.IsDir() {
        err = os.RemoveAll(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.RemoveAll(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4)
        if err != nil {
          fmt.Println("Warning: no " + cur_val4 + " in sas state")
        }
      } else {
        err = os.Remove(file)
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
        err = os.RemoveAll(base_dir + cur_val3 + "/" + branch + "/sas/" + cur_val4)
        if err != nil {
          fmt.Println("Warning: no " + cur_val4 + " in sas state")
        }
      }
    }
    return
  }

  if frst_arg == "branchmy" {
    if n > 2 {
      fmt.Println("Too much args")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    fmt.Println(branch)
    return
  }

  if frst_arg == "branchlist" {
    if n > 2 {
      fmt.Println("Too much args")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/branches.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    fmt.Printf("%v", branch)
    return
  }

  if frst_arg == "branchswitch" {
    if n < 3 {
      fmt.Println("Error: not enough args")
      return
    }
    if n > 3 {
      fmt.Println("Error: not enough args")
      return
    }
    swtch_branch := os.Args[2]
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, err = ExistDirFile(&swtch_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: swicth branch does not exist")
      return
    }
    err = os.WriteFile(base_dir + cur_val3 + "/cur_branch.txt", 
                       []byte(swtch_branch), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_val2 = base_dir + cur_val3 + "/" + swtch_branch
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    str_data = string(data)
    if str_data == "" {
      fmt.Println("No commit has never been taken in", swtch_branch)
      return
    }
    cur_val2 += ("/data/" + str_data + "/data")
    entries, err := os.ReadDir(cur_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    for _, vl := range entries {
      if vl.IsDir() {
        err = os.RemoveAll(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Remove(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    err = deCompressCopyDir(&cur_val2, &cur_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "branchrm" {
    if n < 3 {
      fmt.Println("Error: not enough args")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much args")
      return
    }
    rm_branch := os.Args[2]
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, cur_val4, err = ExistDirFile3(&rm_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: branch to remove does not exist")
      return
    }
    err = os.WriteFile(cur_val, []byte(cur_val4), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.RemoveAll(base_dir + cur_val3 + "/" + rm_branch)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "branchmv" {
    if n < 4 {
      fmt.Println("Error: not enough args")
      return
    }
    if n > 4 {
      fmt.Println("Error: too much args")
      return
    }
    frst_branch := os.Args[2]
    scd_branch := os.Args[3]
    if frst_branch == scd_branch {
      fmt.Println("Branch to renaming should have a different name")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, cur_val4, err = ExistDirFile3(&frst_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: branch to rename does not exist")
      return
    }
    is_valid, err = ExistDirFile(&scd_branch, &cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if is_valid {
      fmt.Println("Error: branch to rename to already exist")
      return
    }
    cur_val4 += "\n"
    cur_val4 += scd_branch
    err = os.WriteFile(cur_val, []byte(cur_val4), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "branchbring" {
    if n < 3 {
      fmt.Println("Error: not enough args, the brnach where the content to bring is, is not mentioned")
      return
    }
    if n < 4 {
      fmt.Println("Error: the content to bring is not mentioned")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    extrn_branch := os.Args[2]
    cur_val2 = base_dir + cur_val3 + "/" + extrn_branch
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    cur_val2 += ("/data/" + string(data))
    cur_val = cur_val2 + "/added.txt"
    var dc_data []byte
    for i = 3; i < n; i++ {
      file = os.Args[i]
      cur_val4 = cur_dir + "/" + file
      is_valid, err = ExistDirFile(&cur_val4, &cur_val)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      if !is_valid {
        fmt.Println("Error: the file " + cur_val4 + " does not exist")
        return
      }
      data, err = os.ReadFile(cur_val2 + "/data/" + file)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      dc_data, err = deCompress(&data)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
      err = os.WriteFile(cur_dir + "/" + file, dc_data, 0644)
      if err != nil {
        fmt.Println("Error:", err)
        return
      }
    }
    return
  }

  if frst_arg == "branchnew" {
    if n < 3 {
      fmt.Println("Error: not enough argument, branch name is required")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    my_branch := os.Args[2]
    ref_branch := my_branch
    cur_val = base_dir + cur_val3 + "/branches.txt"
    is_valid, err = ExistDirFile(&my_branch, &cur_val)
    if err != nil {
      fmt.Println(err)
      return
    }
    if is_valid {
      fmt.Println("Error: Branch name already used")
      return
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    my_branch = base_dir + cur_val3 + "/" + my_branch
    err = os.Mkdir(my_branch, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = CopyDir(&cur_val2, &my_branch)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (ref_branch + "\n")
    err = os.WriteFile(cur_val, 
                      []byte(str_data), 
                      0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitlast" {
    if n > 2 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    data, err = os.ReadFile(cur_val2 + "/cur_commit.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Println(string(data))
    return
  }

  if frst_arg == "commitlist" {
    if n > 2 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    cur_val = ""
    i2 = 0
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        i2 += 1
        fmt.Println("commit -", i2 - 1, ":", cur_val)
        cur_val = ""
      }
    }
    return
  }

  if frst_arg == "commitdiff" {
    if n < 6 {
      fmt.Println("Error: not enough arguments")
      return
    }
    if n > 6 {
      fmt.Println("Error: too much arguments")
      return
    }
    commit1 := os.Args[2]
    commit2 := os.Args[3]
    if commit1 == commit2 {
      fmt.Println("Error: can't express a diff between same comit")
      return
    }
    content1 := os.Args[4]
    content2 := os.Args[5]
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    var commit_hist []string
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    ref_cur_val2 := cur_val2
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    if str_data == "" {
      fmt.Println("Error: No commit found")
      return
    }
    cur_val = ""
    for i = 0; i < len(str_data); i++ {
      if str_data[i] == '\n' {
        cur_val += string(str_data[i])
      } else {
        commit_hist = append(commit_hist, cur_val)
        cur_val = ""
      }
    }
    int_commit1 := StringToInt(commit1)
    if int_commit1 < 0 {
      fmt.Println("Error: the first commit begins at 0")
      return
    }
    if int_commit1 > len(commit_hist) {
      fmt.Println("Error: the last commit is", len(commit_hist) - 1)
      return
    }
    int_commit2 := StringToInt(commit2)
    if int_commit2 < 0 {
      fmt.Println("Error: the first commit begins at 0")
      return
    }
    if int_commit2 > len(commit_hist) {
      fmt.Println("Error: the last commit is", len(commit_hist) - 1)
      return
    }
    cur_val4 = cur_val2 + "/" + commit_hist[int_commit2] + "/added.txt"
    cur_val = cur_dir + "/" + content1
    is_valid, err = ExistDirFile(&cur_val, &cur_val4)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: the file " + content1 + " does not exist in fisrt commit provided")
      return
    }
    cur_val2 += ("/" + commit_hist[int_commit1] + "/added.txt")
    cur_val = cur_dir + "/" + content2
    is_valid, err = ExistDirFile(&cur_val, &cur_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: the file " + content2 + " does not exist in second commit provided")
      return
    }
    cur_val4 = ref_cur_val2 + "/" + commit_hist[int_commit2] + "/" + content2
    ref_cur_val2 += "/" + commit_hist[int_commit1] + "/" + content1
    cur_sep := " | "
    err = DisplayDiff(&ref_cur_val2, &cur_val4, &cur_sep)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitstructdiff" {
    if n < 4 {
      fmt.Println("Error: not enough arguments")
      return
    }
    if n > 4 {
      fmt.Println("Error: too much arguments")
      return
    }
    content1 := os.Args[2]
    content2 := os.Args[3]
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    int_content1 := StringToInt(content1)
    int_content2 := StringToInt(content2)
    if int_content1 == int_content2 {
      fmt.Println("Error: can(t express a diff between same commit)")
      return
    }
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    var hist_commit []string
    str_data = string(data)
    cur_val = ""
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        hist_commit = append(hist_commit, cur_val)
        cur_val = ""
      }
    }
    if int_content1 < 0 || int_content2 < 0 {
      fmt.Println("Error: the first commit begins at 0")
      return
    }
    if int_content1 > len(hist_commit) || int_content2 > len(hist_commit) {
      fmt.Println("Error: the last comit is ", len(hist_commit) - 1)
      return
    }
    content1 = hist_commit[int_content1]
    content2 = hist_commit[int_content2]
    cur_val4 = cur_val2 + "/data/" + content2 + "/added.txt"
    cur_val2 = cur_val2 + "/data/" + content1 + "/added.txt"
    cur_sep := " | "
    fmt.Println("The left commit is:", content1)
    fmt.Println("The right commit is:", content2)
    fmt.Println("####")
    err := DisplayDiffCommit(&cur_val2, &cur_val4, &cur_sep)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitgoback" {
    if n < 3 {
      fmt.Println("Error: not enough arguments")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much arguments")
      return
    }
    cur_val4 = os.Args[2]
    i2 = StringToInt(cur_val4)
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    cur_val2 = base_dir + cur_val3
    data, err = os.ReadFile(cur_val2 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    my_branch := string(data)
    cur_val2 += ("/" + my_branch)
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error: ")
      return
    }
    str_data = string(data)
    cur_val = ""
    var i3 int = 0
    for i = 0; i < len(str_data); i++ {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        if i2 == i3 {
          if cur_val == "" {
            fmt.Println("Error: the commit name is empty")
            return
          }
          break
        }
        cur_val = ""
        i3 += 1
      }
    }
    if i2 != i3 {
      fmt.Println("Error: the commit you are trying to go back doesn't exist")
      return
    }
    err = os.WriteFile(cur_val2 + "/cur_commit.txt", []byte(cur_val), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (cur_val + "\n")
    err = os.WriteFile(cur_val2 + "/commits.txt", []byte(str_data), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    entries, err := os.ReadDir(cur_dir)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    for _, vl := range entries {
      if vl.IsDir() {
        err = os.RemoveAll(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      } else {
        err = os.Remove(vl.Name())
        if err != nil {
          fmt.Println("Error:", err)
          return
        }
      }
    }
    cur_val2 += ("/data/" + cur_val + "/data")
    err = deCompressCopyDir(&cur_val2, &cur_dir)
    fmt.Println("okokl")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "sethost" {
    if n < 3 {
      fmt.Println("Error: not enough argument, the ip and port must be provided")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    host_vl := os.Args[2]
    is_valid, rtn_msg := VerifHost(&host_vl)
    if !is_valid {
      fmt.Println("Error:", rtn_msg)
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    err = os.WriteFile(base_dir + cur_val3 + "/host_info.txt", 
                             []byte(host_vl), 
                             0644)
    if err != nil {
      fmt.Println("Error", err)
      return
    }
    return
  }

  if frst_arg == "commit" {
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    if n < 3 {
      fmt.Println("Error: the message is not provided")
      return
    }
    message := os.Args[2]
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(cur_val2 + "/is_pushed.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    if str_data != "1" {
      fmt.Println("Error: no data has been pushed since last commit or no data has ever been comited")
      return
    }
    commit, err := TreeSum(cur_val2 + "/sas/.")
    str_commit := hex.EncodeToString(commit[:])
    cur_val4 = cur_val2 + "/commits.txt"
    is_valid, err = ExistDirFile(&str_commit, &cur_val4)
    fmt.Println("commit hash:", str_commit)
    if is_valid {
      fmt.Println("Error: the exacts content are found in the previous commit " + str_commit, " consider doing a 'commitgback' if you want to make this your last commit, or that's already your last commit, check this by doing 'commitlast'")
      return
    }
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    tmp_val2 := cur_val2 + "/data/" + str_commit
    err = os.Mkdir(tmp_val2, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    tmp_val2 += "/data"
    err = os.Mkdir(tmp_val2, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    tmp_val := cur_val2 + "/sas"
    err = CopyDir(&tmp_val, &tmp_val2)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.RemoveAll(tmp_val)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.Mkdir(tmp_val, 0755)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val2 + "/cur_added.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/data/" + str_commit + "/added.txt", 
                       data,
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/cur_added.txt", 
                      []byte(cur_dir + "\n"), 
                      0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/data/" + str_commit + "/message.txt", 
                       []byte(message),
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    str_data += (str_commit + "\n")
    err = os.WriteFile(cur_val2 + "/commits.txt", 
                       []byte(str_data), 
                       0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/is_pushed.txt", []byte("0"), 0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    err = os.WriteFile(cur_val2 + "/cur_commit.txt", 
                      []byte(str_commit), 
                      0644)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    return
  }

  if frst_arg == "commitmsg" {
    if n < 3 {
      fmt.Println("Error: not enough argument")
      return
    }
    if n > 3 {
      fmt.Println("Error: too much argument")
      return
    }
    tmp_val := os.Args[2]
    i2 = StringToInt(tmp_val)
    var i3 int = 0
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/cur_branch.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    branch := string(data)
    cur_val2 = base_dir + cur_val3 + "/" + branch
    data, err = os.ReadFile(cur_val2 + "/commits.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    str_data = string(data)
    cur_val = ""
    i = 0
    for i < len(str_data) {
      if str_data[i] != '\n' {
        cur_val += string(str_data[i])
      } else {
        if i3 == i2 {
          if cur_val == "" {
            fmt.Println("Error: the commit name is empty")
            return
          }
          break
        }
        cur_val = ""
        i3 += 1
      }
      i++
    }
    data, err = os.ReadFile(cur_val2 + "/data/" + cur_val + "/message.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Println(string(data))
    return
  }

  if frst_arg == "hostinfo" {
    if n > 2 {
      fmt.Println("Error: too much argument")
      return
    }
    is_valid, err = ExistDirFile(&cur_dir, &initiated_repo)
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    if !is_valid {
      fmt.Println("Error: repo not initialized")
      return
    }
    cur_val3 = ""
    for i = 0; i < len(cur_dir); i++ {
      if cur_dir[i] == '/' {
        cur_val3 += "_"
      } else {
        cur_val3 += string(cur_dir[i])
      }
    }
    data, err = os.ReadFile(base_dir + cur_val3 + "/host_info.txt")
    if err != nil {
      fmt.Println("Error:", err)
      return
    }
    fmt.Println(string(data))
    return
  }

  //if frst_arg == "send" {
  //  
  //}

  //if frst_arg == "sync" {

  //}

  fmt.Println("Error: command not found, try 'help' command")
  return
}


