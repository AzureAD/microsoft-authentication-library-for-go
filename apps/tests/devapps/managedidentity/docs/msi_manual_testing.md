# Running Managed Identity Sources

This file will talk you through the steps required to run the each of the Managed Identity Sources locally

## Setup Virtual Environment and Run Tests for IMDS

To test locally we will require a virtual machine, which we can set up in [Azure](https://portal.azure.com/?feature.tokencaching=true&feature.internalgraphapiversion=true#home)
The next few steps will go over each step of the process, from creating resource groups to managed identity

### Setup Resource Group

We need to set up a resource group that our virtual machine will use

1. On the Azure home screen linked above, you should see **'Resource Groups'**, click this
2. Click **'Create'**
3. Select your Subscription, and below that enter a Resource Group name, such as ***'go-lang-rg'***
4. Select a region, for example **'West Europe'**
5. At the bottom of the screen click **'Review + Create'**
6. At the bottom of the screen click **'Create'**
7. Your resource group is created, you can now go back to the Azure homepage

### Setup Virtual Machine

Next, we need to set up a Virtual Machine for IMDS to run on. Make sure you are on the Azure Homepage

1. Click **'Create a Resource'**
2. Under **'Virtual Machine'** click **'Create'**
3. Select the same Subscription you did for the Resource Group creation
4. Under Resource Group you should see the one you created prior, in this example, ***'go-lang-rg'***. Select it
5. Create a name for your Virtual Machine, such as ***'go-lang-machine'***
6. Select the region, such as West Europe
7. Most of the options can be kept the same

```
- Availability Options = Availability Zone
- Zone Options = Self Selected Zone
- Security Type = Trusted Launch Virtual Machines
- Image = Ubuntu Server 24.04 LTS -x64 Gen2
- VM Architecture = x64
- Run with Azure Spot Discount = Off
- Size = Standard_D2s_v3 - 2 vcpus, 8 GiB memory
- Enable Hibernation = Off
- Authentication Type = SSH Public Key
- SSH Public Key Source = Generate New Key Pair
- SSH Key Type = RSA SSH Format
- Public Inbound Ports = Allow Selected Ports
- Select Inbound Ports = SSH(22)
```

8. For username, enter whatever you want, for example ***'go-lang-machine'***
9. For Key Pair Name, set it to whatever you want, i.e ***'go-lang-machine-key'***
10. At the bottom of the screen click on **'Review + Create'**
11. Click **'Create'** at the bottom of the next page
12. You will see a popup to Generate a New Key Pair
13. Click **'Download private key and create resource'**
14. Once downloaded it should redirect to a page that shows the Virtual Machine deployment. When it completes you can go back to the Home Screen
15. To do the following steps you need to ensure you Virtual Machine is running. On the homepage you can see your virtual machine i.e ***'go-lang-machine'***, click on it
16. In the **'Overview'** of the virtual machine, you can see if it is started or not. If it is not started click on **'Start'**
17. Go back to the homepage

### Setup Local Machine

The next step involves using SSH and setting up the repo on the Virtual Machine
In this example it is done using Mac, if using Windows just make the required adjustments

1. You should have the private key downloaded using the name you set previously, i.e ***'go-lang-machine-key'***. In this example the key is saved in the Downloads folder
2. Open up Terminal
3. Run the following command, using the key name name you setup prior, in this case `chmod 700 go-lang-machine-key.pem`
4. On your Azure home page, click into your Virtual Machine that you created prior, i.e ***'go-lang-machine'***
5. In the left hand panel click expand the **'Connect'** section, and click on **'Connect'**
6. Select the **'Native SSH'** option
7. In the 3rd section copy the command shown i.e `ssh -i ~/Downloads/KEY-NAME.pem VIRTUAL-MACHINE-NAME@PUBLIC-IP-ADDRESS`
8. In Terminal, run the command you copied
9. It will ask you if you are sure you want to continue connecting, type **'yes'**, this will add your public IP to the list of known hosts
10. We should now be connected to the VM via SSH, if not, run the command again
11. Clone our library by calling `git clone https://github.com/AzureAD/microsoft-authentication-library-for-go.git`
12. **cd** into `microsoft-authentication-library-for-go/`
13. Change to whatever branch you want to test on i.e `git switch YOUR_BRANCH_NAME`
14. Perform an update with this command `sudo apt-get update`
15. Install go via `sudo apt-get install golang`, it might ask are you sure you want to install, say yes
16. **cd** into `apps/tests/devapps/managedidentity`
17. Run `go run managedidentity_sample.go`
18. You should see any changes be committed to the SSH instance of the library, and receive some error along the lines of **"Identity not found"**
19. The next steps will talk through running System Assigned and User Assigned

### Run System Assigned Test

1. From the Azure homepage click on your virtual machine
2. In the left hand menu click on Security, and then Identity
3. You should see two tabs, System Assigned and User Assigned. Click on System Assigned if not already accepted
4. Click Status so it is **'On'**
5. Click Save and then Yes
6. Wait for it to finish
7. When done, run the command from step 15 in **'Setup Local Machine'**
8. You should see **'token expire at :  some expiry date'**, where **'some expiry date'** is an expiry that is not all 0's, i.e
`2024-09-26 22:05:11.532734044 +0000 UTC m=+86400.490900710`

### Run User Assigned Test

1. From Azure homepage click on **'Create a resource'**
2. Search for **'Managed Identity'**
3. You should see **'User Assigned Managed Identity'**, under it click **'Create'**
4. Under **'Create'** click on **'User Assigned Managed Identity'**
5. Select your subscription
6. Select the resource group you created earlier
7. Select your region, i.e West Europe
8. Put in a name i.e ***'go-lang-mi'***
9. Click **'Review + Create'** at the bottom of the page
10. Click on **'Create'** at the bottom
11. When it is deployed go back to the Azure homepage
12. Click on the virtual machine you created earlier
13. In the left hand panel click on **'Security'**, in the expanded menu click on **'Identity'**
14. At the top select the **'User Assigned'** tab
15. Click on **'Add'**
16. When it has deployed click into the managed identity in the User Assigned tab
17. Copy the client ID
18. In your local instance of **'microsoft-authentication-library-for-go'**, open `managedidentity_sample.go`
19. Change the following:
```
'miSystemAssigned, err := mi.New(mi.SystemAssigned())' 
```
to be
```
'miUserAssigned, err := mi.New(mi.UserAssignedClientID(CLIENT_ID_YOU_COPIED))'
```
20. Update anything that was previously `miSystemAssigned`, to be `miUserAssigned`
21. Run the command from step 15 in **'Setup Local Machine'**
22. You should see **'token expire at :  some expiry date'**, where **'some expiry date'** is an expiry that is not all 0's, i.e
`2024-09-26 22:05:11.532734044 +0000 UTC m=+86400.490900710`

## Useful command for local testing

This command first synchronizes the local microsoft-authentication-library-for-go directory (including code changes), with the corresponding directory on a remote virtual machine using rsync. After the synchronization, it connects to the remote machine via SSH and runs the go application in the correct directory.
This is useful when the developer is not working on the server machine itself

```
rsync -avz -e "ssh -i PATH_TO_YOUR_PEM_FILE.pem" PATH_TO_THE_GO_LIB/microsoft-authentication-library-for-go/VIRTUAL-MACHINE-NAME@PUBLIC-IP-ADDRESS:/home/VIRTUAL-MACHINE-NAME/PATH_TO_GO_LIB/microsoft-authentication-library-for-go && ssh -i PATH_TO_YOUR_PEM_FILE.pem VIRTUAL-MACHINE-NAME@PUBLIC-IP-ADDRESS 'cd microsoft-authentication-library-for-go/apps/tests/devapps/managedidentity && go run managedidentity_sample.go'
```