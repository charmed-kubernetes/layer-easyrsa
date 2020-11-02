# EasyRSA

This charm delivers the EasyRSA application to act as a Certificate Authority
(CA) and creates certificates for related charms.

EasyRSA is a command line utility to build and manage Public Key 
Infrastructure (PKI) Certificate Authority (CA).

The purpose of a Public Key Infrastructure (PKI) is to facilitate the secure
electronic transfer of information.

This charm is maintained along with the components of Charmed Kubernetes. For full information,
please visit the [official Charmed Kubernetes docs](https://www.ubuntu.com/kubernetes/docs/charm-easyrsa).

## Actions

This section covers Juju actions supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions easyrsa`. If the charm is not
deployed then see file `actions.yaml`.

* `backup`
* `delete-backup`
* `list-backups`
* `restore`

### Create Backups

Use juju action `backup` to capture current snapshot of the easyrsa pki. The 
backup archive is stored on the unit and can be retrieved using `juju scp`
command. Destination where all the backups are stored is 
`/home/ubuntu/easyrsa_backup` and every backup file follows naming convention
`easyrsa-YYYY-MM-DD_HH-MM-SS.tar.gz`. For convenience, the exact `juju scp`
command to download the backup you just created is part of the action's output.

Example:

    juju run-action --wait easyrsa/0 backup

### List Backups

Use juju action `list-backups` to list all available backup archives on the
unit. These names can be used either directly as a parameters for the
`restore` and `delete-backup` actions or to download these backup archives from
the unit, using `juju scp`. The backup file names are relative to the directory
`/home/ubuntu/easyrsa_backup/`, so, for example, to download backup named 
`easyrsa-2020-06-10_16-37-54.tar.gz`, corresponding `juju scp` command would
be:

    juju scp easyrsa/0:/home/ubuntu/easyrsa_backup/easyrsa-2020-06-10_16-37-54.tar.gz .

### Delete Backups

To delete backup stored on the unit, simply run action `delete-backup` with
parameter `name=<backup_name>`. List of all available backups can be
obtained by running action `list-backups`. To remove all the backups from the
unit, you can specify parameter `all=true`.

Remove single backup example:

    juju run-action --wait easyrsa/0 delete-backup name=easyrsa-2020-06-10_16-37-54.tar.gz
    
Remove all backups example:

    juju run-action --wait easyrsa/0 delete-backup all=true


### Restore Backups

To restore easyrsa backup, run `restore` action. This action takes one
parameter `name` that specifies which backup file should be restored. List of
all available backups can be obtained by running action `list-backups`.

Example:

    juju run-action --wait easyrsa/0 restore name=easyrsa-2020-06-10_16-37-54.tar.gz

 > **Important**: The easyrsa charm notifies all the related units that the CA
  and issued certificates changed. It's up to the implementation of each
  related charm to react to this change properly. It may take up to several
  minutes for model to settle back into the `active/idle` state.
  
> **Note**: It may happen that some units were added to the model after the
  backup was created and therefore, there is no certificate associated with
  them in the backup. In such case, easyrsa will issue new certificates to these
  units.
  
> **Known Issue**: It has been observed that the `kubernetes-master` units
  need to be restarted after the certificate change. They may settle into the
  `active/idle` state but all new pods will hang in the `pending` state.

