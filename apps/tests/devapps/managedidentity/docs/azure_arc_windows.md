# Setting Up Azure Arc on Windows

### Step 1:Prerequisites For Windows

1. **Development Environment**: Download Windows or use Hyper-V to create an Windows VM.

- [Microsoft Hyper-V Documentation](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/)

### Step 1.1: Enable Hyper-V

1. **Open Control Panel**.
2. Navigate to **Programs** > **Turn Windows features on or off**.
3. Check the box for **Hyper-V** and click **OK**.
4. Restart your computer if prompted.

### Step 1.2: Open Hyper-V Manager

1. Press `Windows + X` and select **Hyper-V Manager**.
2. If it’s not listed, you can search for it in the Start menu.

### Step 1.3: Create a New Virtual Machine

1. In Hyper-V Manager, select your computer name from the left pane.
2. In the right pane, click on **New** > **Virtual Machine**.
3. Click **Next** on the Wizard.

#### Step 1.3.1: Specify Name and Location

- Enter a name for your VM.
- Optionally, specify a different location to store the VM files.
- Click **Next**.

#### Step 1.3.2: Specify Generation

- Choose between **Generation 1** and **Generation 2** based on your needs (Gen 2 is recommended for newer OS).
- Click **Next**.

#### Step 1.3.3: Assign Memory

- Specify the amount of memory (RAM) for your VM.
- You can also enable **Dynamic Memory** if desired.
- Click **Next**.

#### Step 1.3.4: Configure Networking

- Select a virtual switch to connect your VM to the network. If you don't have one, you'll need to create it.
- Click **Next**.

#### Step 1.3.5: Connect Virtual Hard Disk

- Choose to create a new virtual hard disk, use an existing one, or attach a virtual disk later.
- Specify the name and size of the new disk.
- Click **Next**.

#### Step 1.3.6: Installation Options

- Choose how you want to install the operating system:
  - Install an operating system from a bootable CD/DVD-ROM.
  - Install an operating system from a bootable ISO file.
  - Install an operating system over the network.
- Follow the prompts to select your installation method and click **Next**.

### Step 1.4: Review and Finish

- Review your settings and click **Finish** to create the VM.

### Step 1.5: Start the Virtual Machine

1. Right-click on the VM you just created in Hyper-V Manager.
2. Click **Start**.
3. Right-click again and select **Connect** to open the VM console.
4. Follow the on-screen instructions to install your operating system.

5. **Administrative Access**: Ensure you have administrative rights on your Powershell.

## Step 2: Access Azure Portal

1. Navigate to the Azure portal: [Azure Portal](https://portal.azure.com/#view/Microsoft_Azure_ArcCenterUX/ArcCenterInfrastructure.ReactView).

## Step 3: Set Up Script for Windows

1. Choose the appropriate setup script for your environment (Windows or Linux).
2. **Download the Script**: It’s recommended to download the script instead of copying and pasting it to avoid issues.

## Step 4: Run the Script

1. Open an **Admin Powershell**.
2. Execute the downloaded script.

## Step 5: Installation and running

1. **Install Go Lang**: [Go Lang](https://go.dev/doc/install)

2. **Clone Microsoft Authentication Library**:
   ```bash
   git clone https://github.com/AzureAD/microsoft-authentication-library-for-go.git
   cd microsoft-authentication-library-for-go
   git switch YOUR_BRANCH_NAME
   ```
3. **Navigate to the managed identity sample**:
   ```bash
   cd apps/tests/devapps/managedidentity
   go run managedidentity_sample.go
   ```

## Step 6 HIMDS(Hybrid IMDS) support for ARC

1.  There is a possibility that the env variables might not be set, in this case we fallback on HIMDS apth
2.  For Windows the file is at path : `\AzureConnectedMachineAgent\himds.exe`
3.  This file will be present when you run the azure script.

### Notes on Environment Variables

- **Windows Environment Variables**: To manage environment variables, you can use PowerShell:

  ```powershell
  Remove-Item -Path Env:\IDENTITY_ENDPOINT
  Remove-Item -Path Env:\IMDS_ENDPOINT

  [System.Environment]::SetEnvironmentVariable("IDENTITY_ENDPOINT", "http://localhost:40342/metadata/identity/oauth2/token", [System.EnvironmentVariableTarget]::User)
  [System.Environment]::SetEnvironmentVariable("IMDS_ENDPOINT", "http://localhost:40342", [System.EnvironmentVariableTarget]::User)
  ```

  This guide should assist you in setting up Azure Arc on your Ubuntu environment effectively. If you encounter any issues, consult the linked resources for additional support.
