In construction...

# NexUs

<img src="logo.jpg" height="720" width="480">

**Welcome to NexUs, a versioning system designed for anonymous collaborative innovation, where your contributions are respected, your autonomy is valued, and every commit tells a story!**

# Philosophy

**Designed to work on Linux filesystems accepting concurrent read of files**

## Do not trust anybody

This versioning enables 2 levels of trust.

During the creation of the NexUs server, the creator of the server can distribute 2 pairs of **RSA keys** to future collaborators of the NexUs project.

One pair of RSA keys is for `standard users`.

Standard users can see any projects available on the NexUs server, download those they want to collaborate on, create branches.... But each of their commits is sent over a specified location on the server reserved for `standard users` to not interfere with the work of `admin users` (distinct with their RSA keys).

An `admin user` can see all the branches standard and admin users have created, download them, look into their `README` or directly into the source code and see what changes they have made. 

A `standard user` can only see `admin users` branches, download them...

And as said before each commit of `standard users` is directly sent over a specified location on the NexUs server reserved for `standard users`. So if a group of `standard users` or a single `standard user` want to work on their own branch and want it to not be modified by others users, they have to name it with a `password` as the end of the branch name for example.

In practice, it may look like this `project_featureA_password`

## Consistency

So any users with a valid pair of RSA keys can download the available NexUs projects on the NexUs server anywhere they want. But the philosophy of NexUs emphases on developping consistency. So if you want to work on the downloaded project branch, be sure to download it in the exact specified filepath.

In practice if a project is named `ssd1_projectdir`, download it in `/home/username/ssd1/projectdir`, because all `_` corresponds to `/` and the project name starts from the `username` in the filepath.

Example:

```
 $ nexus seeproject 123.123.123.123:8080
ssd1_projectdir
ssd1_projectdir2
ssd1_projectdir3
 $ mkdir ssd1
 $ mkdir ssd1/projectdir
 $ cd ssd1/projectdir
ssd1/projectdir $ nexus seebranch 123.123.12.123:8080@ssd1_projectdir
main
featureA
featureB
featureC
ssd1/projectdir $ nexus branchget 123.123.123.123:8080@ssd1_projectdir/main
ssd1/projectdir $ nexus bring ssd1_projectdir
```

## Define a directory where all the NexUs projects are stored

The clien let you choose the directory where all the contents are loaded from.

This can be achived by changing the value of `base_dir` at line 20 of `client.go`, must ends with a `/`, example: `"/home/kvv/ssd1/NexUs/dir_client/"` 

## What happen when i add?

When you add files and/or directories before commiting changes, they are stored in the `base_dir/project_name/branchname/sas` directory.

At this point you can remove what is in the `base_dir/project_name/branchname/sas` directory with `nexus rm`

## Automatic adding

Because after each commit, you have to manually add all the directories, files you have to for your current branch of the project, the `addorder` command is here to simplify this process.

To create an `addorder`, do:

```
ssd1/projectdir $ nexus addordernew file1.txt file2.txt dirA dirA/* ...
```

To see the content of `addorder` do:

```
ssd1/projectdir $ nexus addordersee
```

To clear the `addorder` do:

```
ssd1/projectdir $ nexus addorderclear
```

Now each time you have to add the changed files do:

```
ssd1/projectdir $ nexus addorder

```

## See changes through commits

A `diff --side-by-side algorithm` is implemented, so you can see the content differences of a file through commits.

Example:

```
ssd1/projectdir $ nexus commitlist
commit - 0 : 3a627f67b013f858703c12c0bf3b6f963d2d2fa1cd88ece57463128323b60e62
commit - 1 : 4a627f67b013f858703c12c0bf3b6f963d2d2fa1cd88ece57463128323b60e62
commit - 2 : 5a627f67b013f858703c12c0bf3b6f963d2d2fa1cd88ece57463128323b60e62
commit - 3 : 6a627f67b013f858703c12c0bf3b6f963d2d2fa1cd88ece57463128323b60e62
ssd1/projectdir $ nexus commitdiff 0 1 a.tx a.txt
sdsd | sdsd
dddfdf | dddfdf
ss | ss //0 changes
```

Now let's talk about how a user can see the filestructure difference through commits

For that a special file is used that tracks in order all the files and directories that are added in each comit process. So to effectively see the filestructure diff through commits, you have to use the `addorder command` for each commit process.

```
ssd1/projectdir $ nexus commitstructdiff 0 1
The left commit is: 3a627f67b013f858703c12c0bf3b6f963d2d2fa1cd88ece57463128323b60e62
The right commit is: 4a627f67b013f858703c12c0bf3b6f963d2d2fa1cd88ece57463128323b60e62
####
ssd1/NexUs/dir_teste4 | ssd1/NexUs/dir_teste4
ssd1/NexUs/dir_teste4/a.txt | ssd1/NexUs/dir_teste4/a.txt
```

To compare the filestrcture of your `sas` content and another commit do:

```
ssd1/projectdir $ nexus sasstructdiff 0
```

## Go back to a previous commit
